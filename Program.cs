using System.ComponentModel;
using System.Diagnostics;
using System.Drawing.Drawing2D;

namespace ZipPoitto;

internal static class Program
{
    [STAThread]
    private static void Main(string[] args)
    {
        ApplicationConfiguration.Initialize();

        var form = new MainForm();
        if (args.Length > 0 && File.Exists(args[0]))
        {
            form.Shown += (_, _) => form.TrySelectZip(args[0]);
        }

        Application.Run(form);
    }
}

internal sealed class MainForm : Form
{
    private readonly RoundedPanel dropPanel = new();
    private readonly Label dropIcon = new();
    private readonly Label dropTitle = new();
    private readonly Label dropHint = new();
    private readonly Button chooseButton = new();
    private readonly Label selectedFileLabel = new();
    private readonly Button extractButton = new();
    private readonly Label statusLabel = new();
    private readonly Button openFolderButton = new();

    private string? selectedZipPath;
    private string? lastOutputDirectory;
    private bool isExtracting;
    private bool closeAfterExtraction;
    private CancellationTokenSource? extractionCancellation;
    private TaskCompletionSource? extractionCompletion;

    private readonly Color background = Color.FromArgb(249, 247, 255);
    private readonly Color card = Color.FromArgb(255, 255, 255);
    private readonly Color lavender = Color.FromArgb(139, 121, 214);
    private readonly Color lavenderSoft = Color.FromArgb(235, 230, 252);
    private readonly Color text = Color.FromArgb(63, 57, 82);
    private readonly Color muted = Color.FromArgb(125, 118, 145);

    public MainForm()
    {
        Text = "ZIPぽいっ";
        StartPosition = FormStartPosition.CenterScreen;
        ClientSize = new Size(620, 590);
        MinimumSize = new Size(560, 560);
        BackColor = background;
        Font = new Font("Yu Gothic UI", 10F, FontStyle.Regular, GraphicsUnit.Point);
        AllowDrop = true;
        AutoScaleMode = AutoScaleMode.Dpi;

        BuildUi();
        WireDragAndDrop(this);
        WireDragAndDrop(dropPanel);
        FormClosing += MainForm_FormClosing;
    }

    private void BuildUi()
    {
        var title = new Label
        {
            Text = "ZIPぽいっ",
            Font = new Font("Yu Gothic UI", 22F, FontStyle.Bold),
            ForeColor = text,
            AutoSize = true,
            Location = new Point(38, 30)
        };

        var subtitle = new Label
        {
            Text = "ZIPファイルだけ、迷わず解凍。",
            Font = new Font("Yu Gothic UI", 10.5F),
            ForeColor = muted,
            AutoSize = true,
            Location = new Point(41, 77)
        };

        dropPanel.Location = new Point(38, 118);
        dropPanel.Size = new Size(544, 240);
        dropPanel.BackColor = card;
        dropPanel.BorderColor = Color.FromArgb(208, 199, 239);
        dropPanel.BorderWidth = 2;
        dropPanel.CornerRadius = 24;
        dropPanel.Cursor = Cursors.Hand;
        dropPanel.Click += (_, _) => ChooseZip();

        dropIcon.Text = "📦";
        dropIcon.Font = new Font("Segoe UI Emoji", 38F);
        dropIcon.AutoSize = true;
        dropIcon.BackColor = Color.Transparent;
        dropIcon.Location = new Point(210, 18);
        dropIcon.Click += (_, _) => ChooseZip();

        dropTitle.Text = "ここにZIPをぽいっ";
        dropTitle.Font = new Font("Yu Gothic UI", 15F, FontStyle.Bold);
        dropTitle.ForeColor = text;
        dropTitle.AutoSize = false;
        dropTitle.Size = new Size(320, 40);
        dropTitle.Location = new Point(112, 110);
        dropTitle.TextAlign = ContentAlignment.MiddleCenter;
        dropTitle.Click += (_, _) => ChooseZip();

        dropHint.Text = "ドラッグ＆ドロップ または ボタンから選択";
        dropHint.Font = new Font("Yu Gothic UI", 9.5F);
        dropHint.ForeColor = muted;
        dropHint.AutoSize = true;
        dropHint.Location = new Point(137, 151);
        dropHint.Click += (_, _) => ChooseZip();

        chooseButton.Text = "ZIPを選ぶ";
        chooseButton.Size = new Size(130, 38);
        chooseButton.Location = new Point(207, 184);
        chooseButton.Click += (_, _) => ChooseZip();

        dropPanel.Controls.AddRange([dropIcon, dropTitle, dropHint, chooseButton]);

        selectedFileLabel.Text = "まだZIPが選ばれていません";
        selectedFileLabel.ForeColor = muted;
        selectedFileLabel.AutoEllipsis = true;
        selectedFileLabel.Size = new Size(544, 26);
        selectedFileLabel.Location = new Point(38, 382);
        selectedFileLabel.TextAlign = ContentAlignment.MiddleCenter;

        extractButton.Text = "解凍する";
        extractButton.Size = new Size(230, 50);
        extractButton.Location = new Point(195, 424);
        extractButton.Enabled = false;
        extractButton.BackColor = lavender;
        extractButton.ForeColor = Color.White;
        extractButton.FlatStyle = FlatStyle.Flat;
        extractButton.FlatAppearance.BorderSize = 0;
        extractButton.Font = new Font("Yu Gothic UI", 11.5F, FontStyle.Bold);
        extractButton.Cursor = Cursors.Hand;
        extractButton.Click += async (_, _) =>
        {
            if (isExtracting)
            {
                extractionCancellation?.Cancel();
                statusLabel.Text = "解凍を中止しています…";
                return;
            }

            await ExtractSelectedZipAsync();
        };

        statusLabel.Text = "解凍先はZIPと同じ場所に自動で作ります";
        statusLabel.ForeColor = muted;
        statusLabel.AutoEllipsis = true;
        statusLabel.Size = new Size(544, 30);
        statusLabel.Location = new Point(38, 489);
        statusLabel.TextAlign = ContentAlignment.MiddleCenter;

        openFolderButton.Text = "解凍したフォルダーを開く";
        openFolderButton.Size = new Size(230, 38);
        openFolderButton.Location = new Point(195, 526);
        StyleSecondaryButton(openFolderButton);
        openFolderButton.Visible = false;
        openFolderButton.Click += (_, _) => OpenOutputFolder();

        Controls.AddRange([
            title,
            subtitle,
            dropPanel,
            selectedFileLabel,
            extractButton,
            statusLabel,
            openFolderButton
        ]);
    }

    private void StyleSecondaryButton(Button button)
    {
        button.BackColor = lavenderSoft;
        button.ForeColor = text;
        button.FlatStyle = FlatStyle.Flat;
        button.FlatAppearance.BorderSize = 0;
        button.Font = new Font("Yu Gothic UI", 10F, FontStyle.Bold);
        button.Cursor = Cursors.Hand;
    }

    private void WireDragAndDrop(Control control)
    {
        control.AllowDrop = true;
        control.DragEnter += (_, e) =>
        {
            if (!isExtracting && ContainsSingleZip(e.Data))
            {
                e.Effect = DragDropEffects.Copy;
                dropPanel.BackColor = lavenderSoft;
            }
            else
            {
                e.Effect = DragDropEffects.None;
            }
        };

        control.DragLeave += (_, _) => dropPanel.BackColor = card;
        control.DragDrop += (_, e) =>
        {
            dropPanel.BackColor = card;
            if (isExtracting)
            {
                return;
            }

            var files = e.Data?.GetData(DataFormats.FileDrop) as string[];
            if (files is { Length: > 0 })
            {
                TrySelectZip(files[0]);
            }
        };
    }

    private static bool ContainsSingleZip(IDataObject? data)
    {
        if (data?.GetData(DataFormats.FileDrop) is not string[] files || files.Length != 1)
        {
            return false;
        }

        return File.Exists(files[0]) &&
               string.Equals(Path.GetExtension(files[0]), ".zip", StringComparison.OrdinalIgnoreCase);
    }

    private void ChooseZip()
    {
        if (isExtracting)
        {
            return;
        }

        using var dialog = new OpenFileDialog
        {
            Title = "解凍するZIPファイルを選んでください",
            Filter = "ZIPファイル (*.zip)|*.zip",
            Multiselect = false,
            CheckFileExists = true
        };

        if (dialog.ShowDialog(this) == DialogResult.OK)
        {
            TrySelectZip(dialog.FileName);
        }
    }

    public void TrySelectZip(string path)
    {
        if (isExtracting)
        {
            return;
        }

        if (!File.Exists(path) || !string.Equals(Path.GetExtension(path), ".zip", StringComparison.OrdinalIgnoreCase))
        {
            MessageBox.Show(
                this,
                "このアプリで解凍できるのは ZIPファイルだけです。",
                "ZIPじゃないみたい",
                MessageBoxButtons.OK,
                MessageBoxIcon.Information);
            return;
        }

        selectedZipPath = path;
        lastOutputDirectory = null;
        selectedFileLabel.Text = $"📦  {Path.GetFileName(path)}";
        selectedFileLabel.ForeColor = text;
        statusLabel.Text = "準備OK。下のボタンを押すだけです";
        statusLabel.ForeColor = muted;
        extractButton.Enabled = true;
        extractButton.Text = "解凍する";
        openFolderButton.Visible = false;
    }

    private async Task ExtractSelectedZipAsync()
    {
        if (isExtracting || selectedZipPath is null)
        {
            return;
        }

        var zipPath = selectedZipPath;
        isExtracting = true;
        extractionCancellation = new CancellationTokenSource();
        extractionCompletion = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var cancellation = extractionCancellation;
        var completion = extractionCompletion;

        extractButton.Enabled = true;
        extractButton.Text = "中止する";
        chooseButton.Enabled = false;
        statusLabel.Text = "もぐもぐ解凍中…";
        statusLabel.ForeColor = lavender;
        UseWaitCursor = true;

        try
        {
            var output = await Task.Run(
                () => SafeZipExtractor.Extract(zipPath, cancellation.Token),
                cancellation.Token);
            lastOutputDirectory = output;
            statusLabel.Text = "できた！ 解凍が終わりました ✨";
            statusLabel.ForeColor = Color.FromArgb(74, 132, 91);
            extractButton.Text = "もう一度解凍する";
            openFolderButton.Visible = true;
        }
        catch (OperationCanceledException)
        {
            statusLabel.Text = "解凍を中止しました";
            statusLabel.ForeColor = muted;
            extractButton.Text = lastOutputDirectory is null ? "解凍する" : "もう一度解凍する";
        }
        catch (ExtractionCleanupException ex)
        {
            statusLabel.Text = "一時フォルダーを削除できませんでした";
            statusLabel.ForeColor = Color.FromArgb(179, 86, 86);
            MessageBox.Show(
                this,
                $"解凍は完了していません。一時フォルダーが残っています。\n\n{ex.TempDirectoryPath}\n\nアプリを閉じたあと、このフォルダーだけを削除してください。",
                "後片付けが必要です",
                MessageBoxButtons.OK,
                MessageBoxIcon.Warning);
            extractButton.Text = "解凍する";
        }
        catch (UnsafeExtractionLocationException ex)
        {
            statusLabel.Text = "この場所からは安全に解凍できません";
            statusLabel.ForeColor = Color.FromArgb(179, 86, 86);
            MessageBox.Show(
                this,
                ex.Message,
                "ローカルのNTFS/ReFSへコピーしてください",
                MessageBoxButtons.OK,
                MessageBoxIcon.Warning);
        }
        catch (TooLargeArchiveException ex)
        {
            statusLabel.Text = "このZIPは大きすぎるので解凍を止めました";
            statusLabel.ForeColor = Color.FromArgb(179, 86, 86);
            MessageBox.Show(this, ex.Message, "安全のため停止しました", MessageBoxButtons.OK, MessageBoxIcon.Warning);
        }
        catch (InvalidDataException)
        {
            statusLabel.Text = "このZIPは解凍できませんでした";
            statusLabel.ForeColor = Color.FromArgb(179, 86, 86);
            MessageBox.Show(
                this,
                "ZIPファイルが壊れているか、対応していない圧縮方式・パスワード付きZIPの可能性があります。",
                "解凍できませんでした",
                MessageBoxButtons.OK,
                MessageBoxIcon.Warning);
        }
        catch (UnauthorizedAccessException)
        {
            statusLabel.Text = "保存先に書き込めませんでした";
            statusLabel.ForeColor = Color.FromArgb(179, 86, 86);
            MessageBox.Show(
                this,
                "この場所にはファイルを作れないようです。ZIPをデスクトップなどに移して、もう一度試してください。",
                "保存できませんでした",
                MessageBoxButtons.OK,
                MessageBoxIcon.Warning);
        }
        catch (Exception ex)
        {
            statusLabel.Text = "解凍できませんでした";
            statusLabel.ForeColor = Color.FromArgb(179, 86, 86);
            MessageBox.Show(
                this,
                $"解凍中にエラーが起きました。\n\n{ex.Message}",
                "エラー",
                MessageBoxButtons.OK,
                MessageBoxIcon.Error);
        }
        finally
        {
            UseWaitCursor = false;
            isExtracting = false;
            if (extractButton.Text == "中止する")
            {
                extractButton.Text = lastOutputDirectory is null ? "解凍する" : "もう一度解凍する";
            }

            extractButton.Enabled = selectedZipPath is not null;
            chooseButton.Enabled = true;
            cancellation.Dispose();
            if (ReferenceEquals(extractionCancellation, cancellation))
            {
                extractionCancellation = null;
            }

            completion.TrySetResult();
        }
    }

    private async void MainForm_FormClosing(object? sender, FormClosingEventArgs e)
    {
        if (!isExtracting || extractionCompletion is null)
        {
            return;
        }

        e.Cancel = true;
        extractionCancellation?.Cancel();
        if (closeAfterExtraction)
        {
            return;
        }

        closeAfterExtraction = true;
        statusLabel.Text = "解凍を中止して後片付けしています…";
        try
        {
            await extractionCompletion.Task;
        }
        finally
        {
            closeAfterExtraction = false;
            BeginInvoke(Close);
        }
    }

    private void OpenOutputFolder()
    {
        if (lastOutputDirectory is null || !Directory.Exists(lastOutputDirectory))
        {
            return;
        }

        try
        {
            Process.Start(new ProcessStartInfo
            {
                FileName = "explorer.exe",
                UseShellExecute = true,
                ArgumentList = { lastOutputDirectory }
            });
        }
        catch (Exception ex)
        {
            MessageBox.Show(
                this,
                $"フォルダーを開けませんでした。\n\n{ex.Message}",
                "フォルダーを開けませんでした",
                MessageBoxButtons.OK,
                MessageBoxIcon.Warning);
        }
    }
}

internal sealed class RoundedPanel : Panel
{
    [DesignerSerializationVisibility(DesignerSerializationVisibility.Hidden)]
    internal int CornerRadius { get; set; } = 20;

    [DesignerSerializationVisibility(DesignerSerializationVisibility.Hidden)]
    internal int BorderWidth { get; set; } = 1;

    [DesignerSerializationVisibility(DesignerSerializationVisibility.Hidden)]
    internal Color BorderColor { get; set; } = Color.LightGray;

    protected override void OnPaint(PaintEventArgs e)
    {
        base.OnPaint(e);
        e.Graphics.SmoothingMode = SmoothingMode.AntiAlias;

        var rect = new Rectangle(1, 1, Width - 3, Height - 3);
        using var path = CreateRoundedRectangle(rect, CornerRadius);
        using var pen = new Pen(BorderColor, BorderWidth);
        e.Graphics.DrawPath(pen, path);
    }

    protected override void OnResize(EventArgs eventargs)
    {
        base.OnResize(eventargs);
        using var path = CreateRoundedRectangle(new Rectangle(0, 0, Width, Height), CornerRadius);
        Region = new Region(path);
        Invalidate();
    }

    private static GraphicsPath CreateRoundedRectangle(Rectangle rect, int radius)
    {
        var diameter = radius * 2;
        var path = new GraphicsPath();

        path.AddArc(rect.X, rect.Y, diameter, diameter, 180, 90);
        path.AddArc(rect.Right - diameter, rect.Y, diameter, diameter, 270, 90);
        path.AddArc(rect.Right - diameter, rect.Bottom - diameter, diameter, diameter, 0, 90);
        path.AddArc(rect.X, rect.Bottom - diameter, diameter, diameter, 90, 90);
        path.CloseFigure();

        return path;
    }
}
