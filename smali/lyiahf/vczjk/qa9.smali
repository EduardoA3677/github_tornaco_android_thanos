.class public final Llyiahf/vczjk/qa9;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field final synthetic $absoluteElevation:F

.field final synthetic $border:Llyiahf/vczjk/se0;

.field final synthetic $color:J

.field final synthetic $content:Llyiahf/vczjk/ze3;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/ze3;"
        }
    .end annotation
.end field

.field final synthetic $elevation:F

.field final synthetic $modifier:Llyiahf/vczjk/kl5;

.field final synthetic $shape:Llyiahf/vczjk/qj8;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/kl5;Llyiahf/vczjk/qj8;JFLlyiahf/vczjk/se0;FLlyiahf/vczjk/ze3;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/qa9;->$modifier:Llyiahf/vczjk/kl5;

    iput-object p2, p0, Llyiahf/vczjk/qa9;->$shape:Llyiahf/vczjk/qj8;

    iput-wide p3, p0, Llyiahf/vczjk/qa9;->$color:J

    iput p5, p0, Llyiahf/vczjk/qa9;->$absoluteElevation:F

    iput-object p6, p0, Llyiahf/vczjk/qa9;->$border:Llyiahf/vczjk/se0;

    iput p7, p0, Llyiahf/vczjk/qa9;->$elevation:F

    iput-object p8, p0, Llyiahf/vczjk/qa9;->$content:Llyiahf/vczjk/ze3;

    const/4 p1, 0x2

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 11

    const/4 v0, 0x0

    check-cast p1, Llyiahf/vczjk/rf1;

    check-cast p2, Ljava/lang/Number;

    invoke-virtual {p2}, Ljava/lang/Number;->intValue()I

    move-result p2

    and-int/lit8 v1, p2, 0x3

    const/4 v2, 0x1

    const/4 v3, 0x2

    if-eq v1, v3, :cond_0

    move v1, v2

    goto :goto_0

    :cond_0
    move v1, v0

    :goto_0
    and-int/2addr p2, v2

    move-object v8, p1

    check-cast v8, Llyiahf/vczjk/zf1;

    invoke-virtual {v8, p2, v1}, Llyiahf/vczjk/zf1;->Oooo0OO(IZ)Z

    move-result p1

    sget-object p2, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    if-eqz p1, :cond_6

    iget-object p1, p0, Llyiahf/vczjk/qa9;->$modifier:Llyiahf/vczjk/kl5;

    iget-object v1, p0, Llyiahf/vczjk/qa9;->$shape:Llyiahf/vczjk/qj8;

    iget-wide v5, p0, Llyiahf/vczjk/qa9;->$color:J

    sget-object v4, Llyiahf/vczjk/il2;->OooO00o:Llyiahf/vczjk/l39;

    invoke-virtual {v8, v4}, Llyiahf/vczjk/zf1;->OooOO0O(Landroidx/compose/runtime/OooO;)Ljava/lang/Object;

    move-result-object v4

    check-cast v4, Llyiahf/vczjk/z12;

    iget v7, p0, Llyiahf/vczjk/qa9;->$absoluteElevation:F

    sget-object v9, Llyiahf/vczjk/m31;->OooO00o:Llyiahf/vczjk/l39;

    invoke-virtual {v8, v9}, Llyiahf/vczjk/zf1;->OooOO0O(Landroidx/compose/runtime/OooO;)Ljava/lang/Object;

    move-result-object v9

    check-cast v9, Llyiahf/vczjk/k31;

    invoke-virtual {v9}, Llyiahf/vczjk/k31;->OooO0OO()J

    move-result-wide v9

    invoke-static {v5, v6, v9, v10}, Llyiahf/vczjk/n21;->OooO0OO(JJ)Z

    move-result v9

    if-eqz v9, :cond_1

    if-eqz v4, :cond_1

    const v9, 0x408c16b4

    invoke-virtual {v8, v9}, Llyiahf/vczjk/zf1;->OoooO(I)V

    const/4 v9, 0x0

    invoke-virtual/range {v4 .. v9}, Llyiahf/vczjk/z12;->OooO00o(JFLlyiahf/vczjk/rf1;I)J

    move-result-wide v5

    invoke-virtual {v8, v0}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    goto :goto_1

    :cond_1
    const v4, 0x408d20bf

    invoke-virtual {v8, v4}, Llyiahf/vczjk/zf1;->OoooO(I)V

    invoke-virtual {v8, v0}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    :goto_1
    iget-object v4, p0, Llyiahf/vczjk/qa9;->$border:Llyiahf/vczjk/se0;

    iget v7, p0, Llyiahf/vczjk/qa9;->$elevation:F

    const/16 v9, 0x18

    invoke-static {p1, v7, v1, v9}, Llyiahf/vczjk/vt6;->Oooo00O(Llyiahf/vczjk/kl5;FLlyiahf/vczjk/qj8;I)Llyiahf/vczjk/kl5;

    move-result-object p1

    if-eqz v4, :cond_2

    iget-object v7, v4, Llyiahf/vczjk/se0;->OooO0O0:Llyiahf/vczjk/gx8;

    new-instance v9, Landroidx/compose/foundation/BorderModifierNodeElement;

    iget v4, v4, Llyiahf/vczjk/se0;->OooO00o:F

    invoke-direct {v9, v4, v7, v1}, Landroidx/compose/foundation/BorderModifierNodeElement;-><init>(FLlyiahf/vczjk/gx8;Llyiahf/vczjk/qj8;)V

    goto :goto_2

    :cond_2
    sget-object v9, Llyiahf/vczjk/hl5;->OooOOO0:Llyiahf/vczjk/hl5;

    :goto_2
    invoke-interface {p1, v9}, Llyiahf/vczjk/kl5;->OooO0oO(Llyiahf/vczjk/kl5;)Llyiahf/vczjk/kl5;

    move-result-object p1

    invoke-static {p1, v5, v6, v1}, Landroidx/compose/foundation/OooO00o;->OooO00o(Llyiahf/vczjk/kl5;JLlyiahf/vczjk/qj8;)Llyiahf/vczjk/kl5;

    move-result-object p1

    invoke-static {p1, v1}, Llyiahf/vczjk/zsa;->OooOooo(Llyiahf/vczjk/kl5;Llyiahf/vczjk/qj8;)Llyiahf/vczjk/kl5;

    move-result-object p1

    sget-object v1, Llyiahf/vczjk/o68;->Oooo00O:Llyiahf/vczjk/o68;

    invoke-static {p1, v0, v1}, Llyiahf/vczjk/me8;->OooO00o(Llyiahf/vczjk/kl5;ZLlyiahf/vczjk/oe3;)Llyiahf/vczjk/kl5;

    move-result-object p1

    new-instance v1, Llyiahf/vczjk/oa9;

    const/4 v4, 0x0

    invoke-direct {v1, v3, v4}, Llyiahf/vczjk/eb9;-><init>(ILlyiahf/vczjk/yo1;)V

    sget-object v3, Llyiahf/vczjk/gb9;->OooO00o:Llyiahf/vczjk/ey6;

    new-instance v3, Landroidx/compose/ui/input/pointer/SuspendPointerInputElement;

    new-instance v5, Llyiahf/vczjk/fb9;

    invoke-direct {v5, v1}, Llyiahf/vczjk/fb9;-><init>(Llyiahf/vczjk/ze3;)V

    const/4 v1, 0x6

    invoke-direct {v3, p2, v4, v5, v1}, Landroidx/compose/ui/input/pointer/SuspendPointerInputElement;-><init>(Ljava/lang/Object;Ljava/lang/Object;Landroidx/compose/ui/input/pointer/PointerInputEventHandler;I)V

    invoke-interface {p1, v3}, Llyiahf/vczjk/kl5;->OooO0oO(Llyiahf/vczjk/kl5;)Llyiahf/vczjk/kl5;

    move-result-object p1

    iget-object v1, p0, Llyiahf/vczjk/qa9;->$content:Llyiahf/vczjk/ze3;

    sget-object v3, Llyiahf/vczjk/op3;->OooOOO:Llyiahf/vczjk/ub0;

    invoke-static {v3, v2}, Llyiahf/vczjk/ch0;->OooO0Oo(Llyiahf/vczjk/o4;Z)Llyiahf/vczjk/lf5;

    move-result-object v3

    iget v4, v8, Llyiahf/vczjk/zf1;->Oooo:I

    invoke-virtual {v8}, Llyiahf/vczjk/zf1;->OooOOO0()Llyiahf/vczjk/ps6;

    move-result-object v5

    invoke-static {v8, p1}, Llyiahf/vczjk/ng0;->Oooo(Llyiahf/vczjk/rf1;Llyiahf/vczjk/kl5;)Llyiahf/vczjk/kl5;

    move-result-object p1

    sget-object v6, Llyiahf/vczjk/af1;->OooO0Oo:Llyiahf/vczjk/ze1;

    invoke-virtual {v6}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    sget-object v6, Llyiahf/vczjk/ze1;->OooO0O0:Llyiahf/vczjk/o24;

    invoke-virtual {v8}, Llyiahf/vczjk/zf1;->OoooOOo()V

    iget-boolean v7, v8, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-eqz v7, :cond_3

    invoke-virtual {v8, v6}, Llyiahf/vczjk/zf1;->OooOO0o(Llyiahf/vczjk/le3;)V

    goto :goto_3

    :cond_3
    invoke-virtual {v8}, Llyiahf/vczjk/zf1;->Oooooo()V

    :goto_3
    sget-object v6, Llyiahf/vczjk/ze1;->OooO0o:Llyiahf/vczjk/ye1;

    invoke-static {v3, v8, v6}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    sget-object v3, Llyiahf/vczjk/ze1;->OooO0o0:Llyiahf/vczjk/ye1;

    invoke-static {v5, v8, v3}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    sget-object v3, Llyiahf/vczjk/ze1;->OooO0oO:Llyiahf/vczjk/ye1;

    iget-boolean v5, v8, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-nez v5, :cond_4

    invoke-virtual {v8}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v5

    invoke-static {v4}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v6

    invoke-static {v5, v6}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v5

    if-nez v5, :cond_5

    :cond_4
    invoke-static {v4, v8, v4, v3}, Llyiahf/vczjk/ix8;->OooOo00(ILlyiahf/vczjk/zf1;ILlyiahf/vczjk/ye1;)V

    :cond_5
    sget-object v3, Llyiahf/vczjk/ze1;->OooO0Oo:Llyiahf/vczjk/ye1;

    invoke-static {p1, v8, v3}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    invoke-static {v0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object p1

    invoke-interface {v1, v8, p1}, Llyiahf/vczjk/ze3;->invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    invoke-virtual {v8, v2}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    return-object p2

    :cond_6
    invoke-virtual {v8}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    return-object p2
.end method
