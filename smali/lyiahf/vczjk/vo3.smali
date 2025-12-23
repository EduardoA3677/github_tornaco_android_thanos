.class public abstract Llyiahf/vczjk/vo3;
.super Llyiahf/vczjk/jl5;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/c0a;
.implements Llyiahf/vczjk/ny6;
.implements Llyiahf/vczjk/ug1;


# instance fields
.field public OooOoOO:Llyiahf/vczjk/be2;

.field public OooOoo:Z

.field public OooOoo0:Llyiahf/vczjk/bf;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/bf;Llyiahf/vczjk/be2;)V
    .locals 0

    invoke-direct {p0}, Llyiahf/vczjk/jl5;-><init>()V

    iput-object p2, p0, Llyiahf/vczjk/vo3;->OooOoOO:Llyiahf/vczjk/be2;

    iput-object p1, p0, Llyiahf/vczjk/vo3;->OooOoo0:Llyiahf/vczjk/bf;

    return-void
.end method


# virtual methods
.method public final OooOO0o()J
    .locals 5

    iget-object v0, p0, Llyiahf/vczjk/vo3;->OooOoOO:Llyiahf/vczjk/be2;

    if-eqz v0, :cond_0

    invoke-static {p0}, Llyiahf/vczjk/yi4;->o00oO0o(Llyiahf/vczjk/l52;)Llyiahf/vczjk/ro4;

    move-result-object v1

    iget-object v1, v1, Llyiahf/vczjk/ro4;->Oooo0OO:Llyiahf/vczjk/f62;

    sget v2, Llyiahf/vczjk/lx9;->OooO0O0:I

    iget v2, v0, Llyiahf/vczjk/be2;->OooO00o:F

    invoke-interface {v1, v2}, Llyiahf/vczjk/f62;->o00Oo0(F)I

    move-result v2

    iget v3, v0, Llyiahf/vczjk/be2;->OooO0O0:F

    invoke-interface {v1, v3}, Llyiahf/vczjk/f62;->o00Oo0(F)I

    move-result v3

    iget v4, v0, Llyiahf/vczjk/be2;->OooO0OO:F

    invoke-interface {v1, v4}, Llyiahf/vczjk/f62;->o00Oo0(F)I

    move-result v4

    iget v0, v0, Llyiahf/vczjk/be2;->OooO0Oo:F

    invoke-interface {v1, v0}, Llyiahf/vczjk/f62;->o00Oo0(F)I

    move-result v0

    invoke-static {v2, v3, v4, v0}, Llyiahf/vczjk/xj0;->OooOo(IIII)J

    move-result-wide v0

    return-wide v0

    :cond_0
    sget-wide v0, Llyiahf/vczjk/lx9;->OooO00o:J

    return-wide v0
.end method

.method public final OooOoo0()V
    .locals 0

    invoke-virtual {p0}, Llyiahf/vczjk/vo3;->o00000oO()V

    return-void
.end method

.method public final o00000OO()V
    .locals 2

    new-instance v0, Llyiahf/vczjk/hl7;

    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    new-instance v1, Llyiahf/vczjk/uo3;

    invoke-direct {v1, v0}, Llyiahf/vczjk/uo3;-><init>(Llyiahf/vczjk/hl7;)V

    invoke-static {p0, v1}, Llyiahf/vczjk/er8;->OooOo0o(Llyiahf/vczjk/c0a;Llyiahf/vczjk/oe3;)V

    iget-object v0, v0, Llyiahf/vczjk/hl7;->element:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/vo3;

    if-eqz v0, :cond_0

    iget-object v0, v0, Llyiahf/vczjk/vo3;->OooOoo0:Llyiahf/vczjk/bf;

    if-nez v0, :cond_1

    :cond_0
    iget-object v0, p0, Llyiahf/vczjk/vo3;->OooOoo0:Llyiahf/vczjk/bf;

    :cond_1
    invoke-virtual {p0, v0}, Llyiahf/vczjk/vo3;->o00000Oo(Llyiahf/vczjk/iy6;)V

    return-void
.end method

.method public abstract o00000Oo(Llyiahf/vczjk/iy6;)V
.end method

.method public final o00000o0()V
    .locals 2

    new-instance v0, Llyiahf/vczjk/dl7;

    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    const/4 v1, 0x1

    iput-boolean v1, v0, Llyiahf/vczjk/dl7;->element:Z

    new-instance v1, Llyiahf/vczjk/to3;

    invoke-direct {v1, v0}, Llyiahf/vczjk/to3;-><init>(Llyiahf/vczjk/dl7;)V

    invoke-static {p0, v1}, Llyiahf/vczjk/er8;->OooOo(Llyiahf/vczjk/c0a;Llyiahf/vczjk/oe3;)V

    iget-boolean v0, v0, Llyiahf/vczjk/dl7;->element:Z

    if-eqz v0, :cond_0

    invoke-virtual {p0}, Llyiahf/vczjk/vo3;->o00000OO()V

    :cond_0
    return-void
.end method

.method public final o00000oO()V
    .locals 2

    iget-boolean v0, p0, Llyiahf/vczjk/vo3;->OooOoo:Z

    if-eqz v0, :cond_1

    const/4 v0, 0x0

    iput-boolean v0, p0, Llyiahf/vczjk/vo3;->OooOoo:Z

    iget-boolean v0, p0, Llyiahf/vczjk/jl5;->OooOoO:Z

    if-eqz v0, :cond_1

    new-instance v0, Llyiahf/vczjk/hl7;

    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    new-instance v1, Llyiahf/vczjk/so3;

    invoke-direct {v1, v0}, Llyiahf/vczjk/so3;-><init>(Llyiahf/vczjk/hl7;)V

    invoke-static {p0, v1}, Llyiahf/vczjk/er8;->OooOo0o(Llyiahf/vczjk/c0a;Llyiahf/vczjk/oe3;)V

    iget-object v0, v0, Llyiahf/vczjk/hl7;->element:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/vo3;

    const/4 v1, 0x0

    if-eqz v0, :cond_0

    invoke-virtual {v0}, Llyiahf/vczjk/vo3;->o00000OO()V

    sget-object v0, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    goto :goto_0

    :cond_0
    move-object v0, v1

    :goto_0
    if-nez v0, :cond_1

    invoke-virtual {p0, v1}, Llyiahf/vczjk/vo3;->o00000Oo(Llyiahf/vczjk/iy6;)V

    :cond_1
    return-void
.end method

.method public abstract o0000Ooo(I)Z
.end method

.method public final o000OOo()V
    .locals 0

    invoke-virtual {p0}, Llyiahf/vczjk/vo3;->o00000oO()V

    return-void
.end method

.method public final ooOO(Llyiahf/vczjk/ey6;Llyiahf/vczjk/fy6;J)V
    .locals 1

    sget-object p3, Llyiahf/vczjk/fy6;->OooOOO:Llyiahf/vczjk/fy6;

    if-ne p2, p3, :cond_2

    iget-object p2, p1, Llyiahf/vczjk/ey6;->OooO00o:Ljava/lang/Object;

    invoke-interface {p2}, Ljava/util/Collection;->size()I

    move-result p3

    const/4 p4, 0x0

    :goto_0
    if-ge p4, p3, :cond_2

    invoke-interface {p2, p4}, Ljava/util/List;->get(I)Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/ky6;

    iget v0, v0, Llyiahf/vczjk/ky6;->OooO:I

    invoke-virtual {p0, v0}, Llyiahf/vczjk/vo3;->o0000Ooo(I)Z

    move-result v0

    if-eqz v0, :cond_1

    iget p1, p1, Llyiahf/vczjk/ey6;->OooO0Oo:I

    const/4 p2, 0x4

    if-ne p1, p2, :cond_0

    const/4 p1, 0x1

    iput-boolean p1, p0, Llyiahf/vczjk/vo3;->OooOoo:Z

    invoke-virtual {p0}, Llyiahf/vczjk/vo3;->o00000o0()V

    return-void

    :cond_0
    const/4 p2, 0x5

    if-ne p1, p2, :cond_2

    invoke-virtual {p0}, Llyiahf/vczjk/vo3;->o00000oO()V

    return-void

    :cond_1
    add-int/lit8 p4, p4, 0x1

    goto :goto_0

    :cond_2
    return-void
.end method
