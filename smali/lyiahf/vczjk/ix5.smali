.class public final Llyiahf/vczjk/ix5;
.super Llyiahf/vczjk/sg5;
.source "SourceFile"


# instance fields
.field public final OooOoO:Ljava/lang/Class;

.field public final OooOoOO:I

.field public final OooOoo0:Z


# direct methods
.method public constructor <init>(Landroid/content/Context;Ljava/lang/Class;IZ)V
    .locals 0

    invoke-direct {p0, p1}, Llyiahf/vczjk/sg5;-><init>(Landroid/content/Context;)V

    iput-object p2, p0, Llyiahf/vczjk/ix5;->OooOoO:Ljava/lang/Class;

    iput p3, p0, Llyiahf/vczjk/ix5;->OooOoOO:I

    iput-boolean p4, p0, Llyiahf/vczjk/ix5;->OooOoo0:Z

    return-void
.end method


# virtual methods
.method public final OooO00o(IIILjava/lang/CharSequence;)Llyiahf/vczjk/dh5;
    .locals 2

    iget-object v0, p0, Llyiahf/vczjk/sg5;->OooO0o:Ljava/util/ArrayList;

    invoke-virtual {v0}, Ljava/util/ArrayList;->size()I

    move-result v0

    add-int/lit8 v0, v0, 0x1

    iget v1, p0, Llyiahf/vczjk/ix5;->OooOoOO:I

    if-gt v0, v1, :cond_0

    invoke-virtual {p0}, Llyiahf/vczjk/sg5;->OooOoO0()V

    invoke-super {p0, p1, p2, p3, p4}, Llyiahf/vczjk/sg5;->OooO00o(IIILjava/lang/CharSequence;)Llyiahf/vczjk/dh5;

    move-result-object p1

    invoke-virtual {p0}, Llyiahf/vczjk/sg5;->OooOo()V

    return-object p1

    :cond_0
    iget-object p1, p0, Llyiahf/vczjk/ix5;->OooOoO:Ljava/lang/Class;

    invoke-virtual {p1}, Ljava/lang/Class;->getSimpleName()Ljava/lang/String;

    move-result-object p1

    new-instance p2, Ljava/lang/IllegalArgumentException;

    const-string p3, "Maximum number of items supported by "

    const-string p4, " is "

    const-string v0, ". Limit can be checked with "

    invoke-static {p3, p1, p4, v0, v1}, Llyiahf/vczjk/ix8;->OooOOOO(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;I)Ljava/lang/StringBuilder;

    move-result-object p3

    const-string p4, "#getMaxItemCount()"

    invoke-static {p3, p1, p4}, Llyiahf/vczjk/ix8;->OooOO0(Ljava/lang/StringBuilder;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    move-result-object p1

    invoke-direct {p2, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw p2
.end method

.method public final addSubMenu(IIILjava/lang/CharSequence;)Landroid/view/SubMenu;
    .locals 1

    iget-boolean v0, p0, Llyiahf/vczjk/ix5;->OooOoo0:Z

    if-eqz v0, :cond_0

    invoke-virtual {p0, p1, p2, p3, p4}, Llyiahf/vczjk/ix5;->OooO00o(IIILjava/lang/CharSequence;)Llyiahf/vczjk/dh5;

    move-result-object p1

    new-instance p2, Llyiahf/vczjk/nx5;

    iget-object p3, p0, Llyiahf/vczjk/sg5;->OooO00o:Landroid/content/Context;

    const/4 p4, 0x0

    invoke-direct {p2, p3, p0, p1, p4}, Llyiahf/vczjk/nx5;-><init>(Landroid/content/Context;Llyiahf/vczjk/sg5;Llyiahf/vczjk/dh5;I)V

    iput-object p2, p1, Llyiahf/vczjk/dh5;->OooOOOO:Llyiahf/vczjk/u79;

    iget-object p1, p1, Llyiahf/vczjk/dh5;->OooO0o0:Ljava/lang/CharSequence;

    invoke-virtual {p2, p1}, Llyiahf/vczjk/u79;->setHeaderTitle(Ljava/lang/CharSequence;)Landroid/view/SubMenu;

    return-object p2

    :cond_0
    new-instance p1, Ljava/lang/UnsupportedOperationException;

    iget-object p2, p0, Llyiahf/vczjk/ix5;->OooOoO:Ljava/lang/Class;

    invoke-virtual {p2}, Ljava/lang/Class;->getSimpleName()Ljava/lang/String;

    move-result-object p2

    const-string p3, " does not support submenus"

    invoke-virtual {p2, p3}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    move-result-object p2

    invoke-direct {p1, p2}, Ljava/lang/UnsupportedOperationException;-><init>(Ljava/lang/String;)V

    throw p1
.end method
