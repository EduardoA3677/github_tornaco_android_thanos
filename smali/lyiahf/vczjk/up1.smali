.class public final Llyiahf/vczjk/up1;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field final synthetic $density:Llyiahf/vczjk/f62;

.field final synthetic $manager:Llyiahf/vczjk/mk9;

.field final synthetic $maxLines:I

.field final synthetic $offsetMapping:Llyiahf/vczjk/s86;

.field final synthetic $onTextLayout:Llyiahf/vczjk/oe3;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/oe3;"
        }
    .end annotation
.end field

.field final synthetic $readOnly:Z

.field final synthetic $showHandleAndMagnifier:Z

.field final synthetic $state:Llyiahf/vczjk/lx4;

.field final synthetic $value:Llyiahf/vczjk/gl9;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/mk9;Llyiahf/vczjk/lx4;ZZLlyiahf/vczjk/oe3;Llyiahf/vczjk/gl9;Llyiahf/vczjk/s86;Llyiahf/vczjk/f62;I)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/up1;->$manager:Llyiahf/vczjk/mk9;

    iput-object p2, p0, Llyiahf/vczjk/up1;->$state:Llyiahf/vczjk/lx4;

    iput-boolean p3, p0, Llyiahf/vczjk/up1;->$showHandleAndMagnifier:Z

    iput-boolean p4, p0, Llyiahf/vczjk/up1;->$readOnly:Z

    iput-object p5, p0, Llyiahf/vczjk/up1;->$onTextLayout:Llyiahf/vczjk/oe3;

    iput-object p6, p0, Llyiahf/vczjk/up1;->$value:Llyiahf/vczjk/gl9;

    iput-object p7, p0, Llyiahf/vczjk/up1;->$offsetMapping:Llyiahf/vczjk/s86;

    iput-object p8, p0, Llyiahf/vczjk/up1;->$density:Llyiahf/vczjk/f62;

    iput p9, p0, Llyiahf/vczjk/up1;->$maxLines:I

    const/4 p1, 0x2

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 11

    check-cast p1, Llyiahf/vczjk/rf1;

    check-cast p2, Ljava/lang/Number;

    invoke-virtual {p2}, Ljava/lang/Number;->intValue()I

    move-result p2

    and-int/lit8 v0, p2, 0x3

    const/4 v1, 0x2

    const/4 v2, 0x1

    const/4 v3, 0x0

    if-eq v0, v1, :cond_0

    move v0, v2

    goto :goto_0

    :cond_0
    move v0, v3

    :goto_0
    and-int/2addr p2, v2

    check-cast p1, Llyiahf/vczjk/zf1;

    invoke-virtual {p1, p2, v0}, Llyiahf/vczjk/zf1;->Oooo0OO(IZ)Z

    move-result p2

    if-eqz p2, :cond_6

    new-instance v4, Llyiahf/vczjk/tp1;

    iget-object v5, p0, Llyiahf/vczjk/up1;->$state:Llyiahf/vczjk/lx4;

    iget-object v6, p0, Llyiahf/vczjk/up1;->$onTextLayout:Llyiahf/vczjk/oe3;

    iget-object v7, p0, Llyiahf/vczjk/up1;->$value:Llyiahf/vczjk/gl9;

    iget-object v8, p0, Llyiahf/vczjk/up1;->$offsetMapping:Llyiahf/vczjk/s86;

    iget-object v9, p0, Llyiahf/vczjk/up1;->$density:Llyiahf/vczjk/f62;

    iget v10, p0, Llyiahf/vczjk/up1;->$maxLines:I

    invoke-direct/range {v4 .. v10}, Llyiahf/vczjk/tp1;-><init>(Llyiahf/vczjk/lx4;Llyiahf/vczjk/oe3;Llyiahf/vczjk/gl9;Llyiahf/vczjk/s86;Llyiahf/vczjk/f62;I)V

    sget-object p2, Llyiahf/vczjk/hl5;->OooOOO0:Llyiahf/vczjk/hl5;

    iget v0, p1, Llyiahf/vczjk/zf1;->Oooo:I

    invoke-virtual {p1}, Llyiahf/vczjk/zf1;->OooOOO0()Llyiahf/vczjk/ps6;

    move-result-object v1

    invoke-static {p1, p2}, Llyiahf/vczjk/ng0;->Oooo(Llyiahf/vczjk/rf1;Llyiahf/vczjk/kl5;)Llyiahf/vczjk/kl5;

    move-result-object p2

    sget-object v5, Llyiahf/vczjk/af1;->OooO0Oo:Llyiahf/vczjk/ze1;

    invoke-virtual {v5}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    sget-object v5, Llyiahf/vczjk/ze1;->OooO0O0:Llyiahf/vczjk/o24;

    invoke-virtual {p1}, Llyiahf/vczjk/zf1;->OoooOOo()V

    iget-boolean v6, p1, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-eqz v6, :cond_1

    invoke-virtual {p1, v5}, Llyiahf/vczjk/zf1;->OooOO0o(Llyiahf/vczjk/le3;)V

    goto :goto_1

    :cond_1
    invoke-virtual {p1}, Llyiahf/vczjk/zf1;->Oooooo()V

    :goto_1
    sget-object v5, Llyiahf/vczjk/ze1;->OooO0o:Llyiahf/vczjk/ye1;

    invoke-static {v4, p1, v5}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    sget-object v4, Llyiahf/vczjk/ze1;->OooO0o0:Llyiahf/vczjk/ye1;

    invoke-static {v1, p1, v4}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    sget-object v1, Llyiahf/vczjk/ze1;->OooO0oO:Llyiahf/vczjk/ye1;

    iget-boolean v4, p1, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-nez v4, :cond_2

    invoke-virtual {p1}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v4

    invoke-static {v0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v5

    invoke-static {v4, v5}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v4

    if-nez v4, :cond_3

    :cond_2
    invoke-static {v0, p1, v0, v1}, Llyiahf/vczjk/ix8;->OooOo00(ILlyiahf/vczjk/zf1;ILlyiahf/vczjk/ye1;)V

    :cond_3
    sget-object v0, Llyiahf/vczjk/ze1;->OooO0Oo:Llyiahf/vczjk/ye1;

    invoke-static {p2, p1, v0}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    invoke-virtual {p1, v2}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    iget-object p2, p0, Llyiahf/vczjk/up1;->$manager:Llyiahf/vczjk/mk9;

    iget-object v0, p0, Llyiahf/vczjk/up1;->$state:Llyiahf/vczjk/lx4;

    invoke-virtual {v0}, Llyiahf/vczjk/lx4;->OooO00o()Llyiahf/vczjk/vl3;

    move-result-object v0

    sget-object v1, Llyiahf/vczjk/vl3;->OooOOO0:Llyiahf/vczjk/vl3;

    if-eq v0, v1, :cond_4

    iget-object v0, p0, Llyiahf/vczjk/up1;->$state:Llyiahf/vczjk/lx4;

    invoke-virtual {v0}, Llyiahf/vczjk/lx4;->OooO0OO()Llyiahf/vczjk/xn4;

    move-result-object v0

    if-eqz v0, :cond_4

    iget-object v0, p0, Llyiahf/vczjk/up1;->$state:Llyiahf/vczjk/lx4;

    invoke-virtual {v0}, Llyiahf/vczjk/lx4;->OooO0OO()Llyiahf/vczjk/xn4;

    move-result-object v0

    invoke-static {v0}, Llyiahf/vczjk/v34;->OooOo0o(Ljava/lang/Object;)V

    invoke-interface {v0}, Llyiahf/vczjk/xn4;->OooOO0o()Z

    move-result v0

    if-eqz v0, :cond_4

    iget-boolean v0, p0, Llyiahf/vczjk/up1;->$showHandleAndMagnifier:Z

    if-eqz v0, :cond_4

    goto :goto_2

    :cond_4
    move v2, v3

    :goto_2
    invoke-static {p2, v2, p1, v3}, Llyiahf/vczjk/sb;->OooOOO(Llyiahf/vczjk/mk9;ZLlyiahf/vczjk/rf1;I)V

    iget-object p2, p0, Llyiahf/vczjk/up1;->$state:Llyiahf/vczjk/lx4;

    invoke-virtual {p2}, Llyiahf/vczjk/lx4;->OooO00o()Llyiahf/vczjk/vl3;

    move-result-object p2

    sget-object v0, Llyiahf/vczjk/vl3;->OooOOOO:Llyiahf/vczjk/vl3;

    if-ne p2, v0, :cond_5

    iget-boolean p2, p0, Llyiahf/vczjk/up1;->$readOnly:Z

    if-nez p2, :cond_5

    iget-boolean p2, p0, Llyiahf/vczjk/up1;->$showHandleAndMagnifier:Z

    if-eqz p2, :cond_5

    const p2, -0x6d5f72

    invoke-virtual {p1, p2}, Llyiahf/vczjk/zf1;->OoooO(I)V

    iget-object p2, p0, Llyiahf/vczjk/up1;->$manager:Llyiahf/vczjk/mk9;

    invoke-static {p2, p1, v3}, Llyiahf/vczjk/sb;->OooOOO0(Llyiahf/vczjk/mk9;Llyiahf/vczjk/rf1;I)V

    invoke-virtual {p1, v3}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    goto :goto_3

    :cond_5
    const p2, -0x6c3322

    invoke-virtual {p1, p2}, Llyiahf/vczjk/zf1;->OoooO(I)V

    invoke-virtual {p1, v3}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    goto :goto_3

    :cond_6
    invoke-virtual {p1}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    :goto_3
    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method
