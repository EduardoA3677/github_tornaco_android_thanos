.class public final Llyiahf/vczjk/d04;
.super Landroid/view/inputmethod/InputConnectionWrapper;
.source "SourceFile"


# instance fields
.field public final synthetic OooO00o:Llyiahf/vczjk/oOO000o;


# direct methods
.method public constructor <init>(Landroid/view/inputmethod/InputConnection;Llyiahf/vczjk/oOO000o;)V
    .locals 0

    iput-object p2, p0, Llyiahf/vczjk/d04;->OooO00o:Llyiahf/vczjk/oOO000o;

    const/4 p2, 0x0

    invoke-direct {p0, p1, p2}, Landroid/view/inputmethod/InputConnectionWrapper;-><init>(Landroid/view/inputmethod/InputConnection;Z)V

    return-void
.end method


# virtual methods
.method public final commitContent(Landroid/view/inputmethod/InputContentInfo;ILandroid/os/Bundle;)Z
    .locals 3

    const/4 v0, 0x0

    if-nez p1, :cond_0

    goto :goto_0

    :cond_0
    sget v1, Landroid/os/Build$VERSION;->SDK_INT:I

    const/16 v2, 0x19

    if-ge v1, v2, :cond_1

    goto :goto_0

    :cond_1
    new-instance v0, Llyiahf/vczjk/tqa;

    new-instance v1, Llyiahf/vczjk/f04;

    invoke-direct {v1, p1}, Llyiahf/vczjk/f04;-><init>(Ljava/lang/Object;)V

    const/16 v2, 0x14

    invoke-direct {v0, v1, v2}, Llyiahf/vczjk/tqa;-><init>(Ljava/lang/Object;I)V

    :goto_0
    iget-object v1, p0, Llyiahf/vczjk/d04;->OooO00o:Llyiahf/vczjk/oOO000o;

    invoke-virtual {v1, v0, p2, p3}, Llyiahf/vczjk/oOO000o;->OooOoO0(Llyiahf/vczjk/tqa;ILandroid/os/Bundle;)Z

    move-result v0

    if-eqz v0, :cond_2

    const/4 p1, 0x1

    return p1

    :cond_2
    invoke-super {p0, p1, p2, p3}, Landroid/view/inputmethod/InputConnectionWrapper;->commitContent(Landroid/view/inputmethod/InputContentInfo;ILandroid/os/Bundle;)Z

    move-result p1

    return p1
.end method
