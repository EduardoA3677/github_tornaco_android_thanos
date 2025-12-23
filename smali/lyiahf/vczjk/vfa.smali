.class public abstract Llyiahf/vczjk/vfa;
.super Ljava/lang/Object;
.source "SourceFile"


# direct methods
.method public static OooO00o(Landroid/view/View;)[Ljava/lang/String;
    .locals 0

    invoke-virtual {p0}, Landroid/view/View;->getReceiveContentMimeTypes()[Ljava/lang/String;

    move-result-object p0

    return-object p0
.end method

.method public static OooO0O0(Landroid/view/View;Llyiahf/vczjk/ym1;)Llyiahf/vczjk/ym1;
    .locals 1

    iget-object v0, p1, Llyiahf/vczjk/ym1;->OooO00o:Llyiahf/vczjk/xm1;

    invoke-interface {v0}, Llyiahf/vczjk/xm1;->Oooo0o0()Landroid/view/ContentInfo;

    move-result-object v0

    invoke-static {v0}, Ljava/util/Objects;->requireNonNull(Ljava/lang/Object;)Ljava/lang/Object;

    invoke-virtual {p0, v0}, Landroid/view/View;->performReceiveContent(Landroid/view/ContentInfo;)Landroid/view/ContentInfo;

    move-result-object p0

    if-nez p0, :cond_0

    const/4 p0, 0x0

    return-object p0

    :cond_0
    if-ne p0, v0, :cond_1

    return-object p1

    :cond_1
    new-instance p1, Llyiahf/vczjk/ym1;

    new-instance v0, Llyiahf/vczjk/uz5;

    invoke-direct {v0, p0}, Llyiahf/vczjk/uz5;-><init>(Landroid/view/ContentInfo;)V

    invoke-direct {p1, v0}, Llyiahf/vczjk/ym1;-><init>(Llyiahf/vczjk/xm1;)V

    return-object p1
.end method
