.class public final Llyiahf/vczjk/rm0;
.super Llyiahf/vczjk/jl5;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/l86;
.implements Llyiahf/vczjk/qj0;
.implements Llyiahf/vczjk/fg2;


# instance fields
.field public final OooOoOO:Llyiahf/vczjk/tm0;

.field public OooOoo:Llyiahf/vczjk/oe3;

.field public OooOoo0:Z


# direct methods
.method public constructor <init>(Llyiahf/vczjk/tm0;Llyiahf/vczjk/oe3;)V
    .locals 0

    invoke-direct {p0}, Llyiahf/vczjk/jl5;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/rm0;->OooOoOO:Llyiahf/vczjk/tm0;

    iput-object p2, p0, Llyiahf/vczjk/rm0;->OooOoo:Llyiahf/vczjk/oe3;

    iput-object p0, p1, Llyiahf/vczjk/tm0;->OooOOO0:Llyiahf/vczjk/qj0;

    return-void
.end method


# virtual methods
.method public final OooO0O0()Llyiahf/vczjk/f62;
    .locals 1

    invoke-static {p0}, Llyiahf/vczjk/yi4;->o00oO0o(Llyiahf/vczjk/l52;)Llyiahf/vczjk/ro4;

    move-result-object v0

    iget-object v0, v0, Llyiahf/vczjk/ro4;->Oooo0OO:Llyiahf/vczjk/f62;

    return-object v0
.end method

.method public final OooO0Oo()V
    .locals 0

    invoke-virtual {p0}, Llyiahf/vczjk/rm0;->o00000OO()V

    return-void
.end method

.method public final OooO0o0()J
    .locals 2

    const/16 v0, 0x80

    invoke-static {p0, v0}, Llyiahf/vczjk/yi4;->o00ooo(Llyiahf/vczjk/l52;I)Llyiahf/vczjk/v16;

    move-result-object v0

    iget-wide v0, v0, Llyiahf/vczjk/ow6;->OooOOOO:J

    invoke-static {v0, v1}, Llyiahf/vczjk/e16;->Oooo0oO(J)J

    move-result-wide v0

    return-wide v0
.end method

.method public final OooOo0o(Llyiahf/vczjk/to4;)V
    .locals 2

    iget-boolean v0, p0, Llyiahf/vczjk/rm0;->OooOoo0:Z

    iget-object v1, p0, Llyiahf/vczjk/rm0;->OooOoOO:Llyiahf/vczjk/tm0;

    if-nez v0, :cond_1

    const/4 v0, 0x0

    iput-object v0, v1, Llyiahf/vczjk/tm0;->OooOOO:Llyiahf/vczjk/gg2;

    new-instance v0, Llyiahf/vczjk/qm0;

    invoke-direct {v0, p0, v1}, Llyiahf/vczjk/qm0;-><init>(Llyiahf/vczjk/rm0;Llyiahf/vczjk/tm0;)V

    invoke-static {p0, v0}, Llyiahf/vczjk/bua;->Oooo000(Llyiahf/vczjk/jl5;Llyiahf/vczjk/le3;)V

    iget-object v0, v1, Llyiahf/vczjk/tm0;->OooOOO:Llyiahf/vczjk/gg2;

    if-eqz v0, :cond_0

    const/4 v0, 0x1

    iput-boolean v0, p0, Llyiahf/vczjk/rm0;->OooOoo0:Z

    goto :goto_0

    :cond_0
    const-string p1, "DrawResult not defined, did you forget to call onDraw?"

    invoke-static {p1}, Llyiahf/vczjk/ix8;->OooOOOo(Ljava/lang/String;)Llyiahf/vczjk/k61;

    move-result-object p1

    throw p1

    :cond_1
    :goto_0
    iget-object v0, v1, Llyiahf/vczjk/tm0;->OooOOO:Llyiahf/vczjk/gg2;

    invoke-static {v0}, Llyiahf/vczjk/v34;->OooOo0o(Ljava/lang/Object;)V

    iget-object v0, v0, Llyiahf/vczjk/gg2;->OooOOO0:Llyiahf/vczjk/oe3;

    invoke-interface {v0, p1}, Llyiahf/vczjk/oe3;->OooO0o(Ljava/lang/Object;)Ljava/lang/Object;

    return-void
.end method

.method public final Oooo00o()V
    .locals 0

    invoke-virtual {p0}, Llyiahf/vczjk/rm0;->o00000OO()V

    return-void
.end method

.method public final Oooo0o0()V
    .locals 0

    invoke-virtual {p0}, Llyiahf/vczjk/rm0;->o00000OO()V

    return-void
.end method

.method public final Oooooo()V
    .locals 0

    invoke-virtual {p0}, Llyiahf/vczjk/rm0;->o00000OO()V

    return-void
.end method

.method public final getLayoutDirection()Llyiahf/vczjk/yn4;
    .locals 1

    invoke-static {p0}, Llyiahf/vczjk/yi4;->o00oO0o(Llyiahf/vczjk/l52;)Llyiahf/vczjk/ro4;

    move-result-object v0

    iget-object v0, v0, Llyiahf/vczjk/ro4;->Oooo0o0:Llyiahf/vczjk/yn4;

    return-object v0
.end method

.method public final o00000OO()V
    .locals 2

    const/4 v0, 0x0

    iput-boolean v0, p0, Llyiahf/vczjk/rm0;->OooOoo0:Z

    iget-object v0, p0, Llyiahf/vczjk/rm0;->OooOoOO:Llyiahf/vczjk/tm0;

    const/4 v1, 0x0

    iput-object v1, v0, Llyiahf/vczjk/tm0;->OooOOO:Llyiahf/vczjk/gg2;

    invoke-static {p0}, Llyiahf/vczjk/ye5;->OooOoO0(Llyiahf/vczjk/fg2;)V

    return-void
.end method

.method public final o000OOo()V
    .locals 0

    return-void
.end method
