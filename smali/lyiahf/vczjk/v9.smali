.class public final Llyiahf/vczjk/v9;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/c01;


# instance fields
.field public final OooO00o:Llyiahf/vczjk/w9;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/w9;)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/v9;->OooO00o:Llyiahf/vczjk/w9;

    return-void
.end method


# virtual methods
.method public final OooO00o(Llyiahf/vczjk/a01;)V
    .locals 2

    iget-object v0, p0, Llyiahf/vczjk/v9;->OooO00o:Llyiahf/vczjk/w9;

    iget-object v0, v0, Llyiahf/vczjk/w9;->OooO00o:Landroid/content/ClipboardManager;

    if-nez p1, :cond_1

    sget p1, Landroid/os/Build$VERSION;->SDK_INT:I

    const/16 v1, 0x1c

    if-lt p1, v1, :cond_0

    invoke-static {v0}, Llyiahf/vczjk/o0O0O0o0;->OooOOO0(Landroid/content/ClipboardManager;)V

    return-void

    :cond_0
    const-string p1, ""

    invoke-static {p1, p1}, Landroid/content/ClipData;->newPlainText(Ljava/lang/CharSequence;Ljava/lang/CharSequence;)Landroid/content/ClipData;

    move-result-object p1

    invoke-virtual {v0, p1}, Landroid/content/ClipboardManager;->setPrimaryClip(Landroid/content/ClipData;)V

    return-void

    :cond_1
    iget-object p1, p1, Llyiahf/vczjk/a01;->OooO00o:Landroid/content/ClipData;

    invoke-virtual {v0, p1}, Landroid/content/ClipboardManager;->setPrimaryClip(Landroid/content/ClipData;)V

    return-void
.end method
