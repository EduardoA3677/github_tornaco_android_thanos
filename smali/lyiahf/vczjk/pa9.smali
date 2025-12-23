.class public final Llyiahf/vczjk/pa9;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field public final synthetic OooOOO:Llyiahf/vczjk/qj8;

.field public final synthetic OooOOO0:Llyiahf/vczjk/kl5;

.field public final synthetic OooOOOO:J

.field public final synthetic OooOOOo:F

.field public final synthetic OooOOo:F

.field public final synthetic OooOOo0:Llyiahf/vczjk/se0;

.field public final synthetic OooOOoo:Llyiahf/vczjk/a91;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/kl5;Llyiahf/vczjk/qj8;JFLlyiahf/vczjk/se0;FLlyiahf/vczjk/a91;)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/pa9;->OooOOO0:Llyiahf/vczjk/kl5;

    iput-object p2, p0, Llyiahf/vczjk/pa9;->OooOOO:Llyiahf/vczjk/qj8;

    iput-wide p3, p0, Llyiahf/vczjk/pa9;->OooOOOO:J

    iput p5, p0, Llyiahf/vczjk/pa9;->OooOOOo:F

    iput-object p6, p0, Llyiahf/vczjk/pa9;->OooOOo0:Llyiahf/vczjk/se0;

    iput p7, p0, Llyiahf/vczjk/pa9;->OooOOo:F

    iput-object p8, p0, Llyiahf/vczjk/pa9;->OooOOoo:Llyiahf/vczjk/a91;

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 12

    check-cast p1, Llyiahf/vczjk/rf1;

    check-cast p2, Ljava/lang/Number;

    invoke-virtual {p2}, Ljava/lang/Number;->intValue()I

    move-result p2

    and-int/lit8 v0, p2, 0x3

    const/4 v1, 0x2

    const/4 v2, 0x0

    const/4 v3, 0x1

    if-eq v0, v1, :cond_0

    move v0, v3

    goto :goto_0

    :cond_0
    move v0, v2

    :goto_0
    and-int/2addr p2, v3

    check-cast p1, Llyiahf/vczjk/zf1;

    invoke-virtual {p1, p2, v0}, Llyiahf/vczjk/zf1;->Oooo0OO(IZ)Z

    move-result p2

    sget-object v0, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    if-eqz p2, :cond_6

    iget-wide v4, p0, Llyiahf/vczjk/pa9;->OooOOOO:J

    iget p2, p0, Llyiahf/vczjk/pa9;->OooOOOo:F

    invoke-static {v4, v5, p2, p1}, Llyiahf/vczjk/ua9;->OooO0o0(JFLlyiahf/vczjk/zf1;)J

    move-result-wide v8

    sget-object p2, Llyiahf/vczjk/ch1;->OooO0oo:Llyiahf/vczjk/l39;

    invoke-virtual {p1, p2}, Llyiahf/vczjk/zf1;->OooOO0O(Landroidx/compose/runtime/OooO;)Ljava/lang/Object;

    move-result-object p2

    iget v1, p0, Llyiahf/vczjk/pa9;->OooOOo:F

    check-cast p2, Llyiahf/vczjk/f62;

    invoke-interface {p2, v1}, Llyiahf/vczjk/f62;->Ooooo00(F)F

    move-result v11

    iget-object v10, p0, Llyiahf/vczjk/pa9;->OooOOo0:Llyiahf/vczjk/se0;

    iget-object v6, p0, Llyiahf/vczjk/pa9;->OooOOO0:Llyiahf/vczjk/kl5;

    iget-object v7, p0, Llyiahf/vczjk/pa9;->OooOOO:Llyiahf/vczjk/qj8;

    invoke-static/range {v6 .. v11}, Llyiahf/vczjk/ua9;->OooO0Oo(Llyiahf/vczjk/kl5;Llyiahf/vczjk/qj8;JLlyiahf/vczjk/se0;F)Llyiahf/vczjk/kl5;

    move-result-object p2

    invoke-virtual {p1}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v1

    sget-object v4, Llyiahf/vczjk/qf1;->OooO00o:Llyiahf/vczjk/tp3;

    if-ne v1, v4, :cond_1

    new-instance v1, Llyiahf/vczjk/xm8;

    const/16 v5, 0x12

    invoke-direct {v1, v5}, Llyiahf/vczjk/xm8;-><init>(I)V

    invoke-virtual {p1, v1}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_1
    check-cast v1, Llyiahf/vczjk/oe3;

    invoke-static {p2, v2, v1}, Llyiahf/vczjk/me8;->OooO00o(Llyiahf/vczjk/kl5;ZLlyiahf/vczjk/oe3;)Llyiahf/vczjk/kl5;

    move-result-object p2

    invoke-virtual {p1}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v1

    if-ne v1, v4, :cond_2

    sget-object v1, Llyiahf/vczjk/y32;->OooOOOo:Llyiahf/vczjk/y32;

    invoke-virtual {p1, v1}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_2
    check-cast v1, Landroidx/compose/ui/input/pointer/PointerInputEventHandler;

    invoke-static {p2, v0, v1}, Llyiahf/vczjk/gb9;->OooO00o(Llyiahf/vczjk/kl5;Ljava/lang/Object;Landroidx/compose/ui/input/pointer/PointerInputEventHandler;)Llyiahf/vczjk/kl5;

    move-result-object p2

    sget-object v1, Llyiahf/vczjk/op3;->OooOOO:Llyiahf/vczjk/ub0;

    invoke-static {v1, v3}, Llyiahf/vczjk/ch0;->OooO0Oo(Llyiahf/vczjk/o4;Z)Llyiahf/vczjk/lf5;

    move-result-object v1

    iget v4, p1, Llyiahf/vczjk/zf1;->Oooo:I

    invoke-virtual {p1}, Llyiahf/vczjk/zf1;->OooOOO0()Llyiahf/vczjk/ps6;

    move-result-object v5

    invoke-static {p1, p2}, Llyiahf/vczjk/ng0;->Oooo(Llyiahf/vczjk/rf1;Llyiahf/vczjk/kl5;)Llyiahf/vczjk/kl5;

    move-result-object p2

    sget-object v6, Llyiahf/vczjk/af1;->OooO0Oo:Llyiahf/vczjk/ze1;

    invoke-virtual {v6}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    sget-object v6, Llyiahf/vczjk/ze1;->OooO0O0:Llyiahf/vczjk/o24;

    invoke-virtual {p1}, Llyiahf/vczjk/zf1;->OoooOOo()V

    iget-boolean v7, p1, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-eqz v7, :cond_3

    invoke-virtual {p1, v6}, Llyiahf/vczjk/zf1;->OooOO0o(Llyiahf/vczjk/le3;)V

    goto :goto_1

    :cond_3
    invoke-virtual {p1}, Llyiahf/vczjk/zf1;->Oooooo()V

    :goto_1
    sget-object v6, Llyiahf/vczjk/ze1;->OooO0o:Llyiahf/vczjk/ye1;

    invoke-static {v1, p1, v6}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    sget-object v1, Llyiahf/vczjk/ze1;->OooO0o0:Llyiahf/vczjk/ye1;

    invoke-static {v5, p1, v1}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    sget-object v1, Llyiahf/vczjk/ze1;->OooO0oO:Llyiahf/vczjk/ye1;

    iget-boolean v5, p1, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-nez v5, :cond_4

    invoke-virtual {p1}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v5

    invoke-static {v4}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v6

    invoke-static {v5, v6}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v5

    if-nez v5, :cond_5

    :cond_4
    invoke-static {v4, p1, v4, v1}, Llyiahf/vczjk/ix8;->OooOo00(ILlyiahf/vczjk/zf1;ILlyiahf/vczjk/ye1;)V

    :cond_5
    sget-object v1, Llyiahf/vczjk/ze1;->OooO0Oo:Llyiahf/vczjk/ye1;

    invoke-static {p2, p1, v1}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    invoke-static {v2}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object p2

    iget-object v1, p0, Llyiahf/vczjk/pa9;->OooOOoo:Llyiahf/vczjk/a91;

    invoke-virtual {v1, p1, p2}, Llyiahf/vczjk/a91;->invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    invoke-virtual {p1, v3}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    return-object v0

    :cond_6
    invoke-virtual {p1}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    return-object v0
.end method
