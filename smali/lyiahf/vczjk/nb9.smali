.class public final Llyiahf/vczjk/nb9;
.super Llyiahf/vczjk/jl5;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/oy6;
.implements Llyiahf/vczjk/f62;
.implements Llyiahf/vczjk/ny6;


# instance fields
.field public OooOoOO:Ljava/lang/Object;

.field public OooOoo:Landroidx/compose/ui/input/pointer/PointerInputEventHandler;

.field public OooOoo0:Ljava/lang/Object;

.field public OooOooO:Llyiahf/vczjk/r09;

.field public OooOooo:Llyiahf/vczjk/ey6;

.field public Oooo0:Llyiahf/vczjk/ey6;

.field public final Oooo000:Llyiahf/vczjk/ws5;

.field public final Oooo00O:Llyiahf/vczjk/ws5;

.field public final Oooo00o:Llyiahf/vczjk/ws5;

.field public Oooo0O0:J


# direct methods
.method public constructor <init>(Ljava/lang/Object;Ljava/lang/Object;Landroidx/compose/ui/input/pointer/PointerInputEventHandler;)V
    .locals 0

    invoke-direct {p0}, Llyiahf/vczjk/jl5;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/nb9;->OooOoOO:Ljava/lang/Object;

    iput-object p2, p0, Llyiahf/vczjk/nb9;->OooOoo0:Ljava/lang/Object;

    iput-object p3, p0, Llyiahf/vczjk/nb9;->OooOoo:Landroidx/compose/ui/input/pointer/PointerInputEventHandler;

    sget-object p1, Llyiahf/vczjk/gb9;->OooO00o:Llyiahf/vczjk/ey6;

    iput-object p1, p0, Llyiahf/vczjk/nb9;->OooOooo:Llyiahf/vczjk/ey6;

    new-instance p1, Llyiahf/vczjk/ws5;

    const/16 p2, 0x10

    new-array p3, p2, [Llyiahf/vczjk/kb9;

    invoke-direct {p1, p3}, Llyiahf/vczjk/ws5;-><init>([Ljava/lang/Object;)V

    iput-object p1, p0, Llyiahf/vczjk/nb9;->Oooo000:Llyiahf/vczjk/ws5;

    iput-object p1, p0, Llyiahf/vczjk/nb9;->Oooo00O:Llyiahf/vczjk/ws5;

    new-instance p1, Llyiahf/vczjk/ws5;

    new-array p2, p2, [Llyiahf/vczjk/kb9;

    invoke-direct {p1, p2}, Llyiahf/vczjk/ws5;-><init>([Ljava/lang/Object;)V

    iput-object p1, p0, Llyiahf/vczjk/nb9;->Oooo00o:Llyiahf/vczjk/ws5;

    const-wide/16 p1, 0x0

    iput-wide p1, p0, Llyiahf/vczjk/nb9;->Oooo0O0:J

    return-void
.end method


# virtual methods
.method public final OooO0O0()F
    .locals 1

    invoke-static {p0}, Llyiahf/vczjk/yi4;->o00oO0o(Llyiahf/vczjk/l52;)Llyiahf/vczjk/ro4;

    move-result-object v0

    iget-object v0, v0, Llyiahf/vczjk/ro4;->Oooo0OO:Llyiahf/vczjk/f62;

    invoke-interface {v0}, Llyiahf/vczjk/f62;->OooO0O0()F

    move-result v0

    return v0
.end method

.method public final OooO0Oo()V
    .locals 0

    invoke-virtual {p0}, Llyiahf/vczjk/nb9;->o00000o0()V

    return-void
.end method

.method public final OooOoo0()V
    .locals 24

    move-object/from16 v0, p0

    iget-object v1, v0, Llyiahf/vczjk/nb9;->Oooo0:Llyiahf/vczjk/ey6;

    if-nez v1, :cond_0

    goto :goto_2

    :cond_0
    iget-object v1, v1, Llyiahf/vczjk/ey6;->OooO00o:Ljava/lang/Object;

    invoke-interface {v1}, Ljava/util/Collection;->size()I

    move-result v2

    const/4 v3, 0x0

    move v4, v3

    :goto_0
    if-ge v4, v2, :cond_3

    invoke-interface {v1, v4}, Ljava/util/List;->get(I)Ljava/lang/Object;

    move-result-object v5

    check-cast v5, Llyiahf/vczjk/ky6;

    iget-boolean v5, v5, Llyiahf/vczjk/ky6;->OooO0Oo:Z

    if-eqz v5, :cond_2

    new-instance v2, Ljava/util/ArrayList;

    invoke-interface {v1}, Ljava/util/List;->size()I

    move-result v4

    invoke-direct {v2, v4}, Ljava/util/ArrayList;-><init>(I)V

    invoke-interface {v1}, Ljava/util/Collection;->size()I

    move-result v4

    :goto_1
    if-ge v3, v4, :cond_1

    invoke-interface {v1, v3}, Ljava/util/List;->get(I)Ljava/lang/Object;

    move-result-object v5

    check-cast v5, Llyiahf/vczjk/ky6;

    iget-wide v7, v5, Llyiahf/vczjk/ky6;->OooO00o:J

    new-instance v6, Llyiahf/vczjk/ky6;

    iget-boolean v9, v5, Llyiahf/vczjk/ky6;->OooO0Oo:Z

    iget v10, v5, Llyiahf/vczjk/ky6;->OooO:I

    move/from16 v19, v9

    move/from16 v21, v10

    iget-wide v9, v5, Llyiahf/vczjk/ky6;->OooO0O0:J

    iget-wide v11, v5, Llyiahf/vczjk/ky6;->OooO0OO:J

    const/4 v13, 0x0

    iget v14, v5, Llyiahf/vczjk/ky6;->OooO0o0:F

    const-wide/16 v22, 0x0

    move-wide v15, v9

    move-wide/from16 v17, v11

    move/from16 v20, v19

    invoke-direct/range {v6 .. v23}, Llyiahf/vczjk/ky6;-><init>(JJJZFJJZZIJ)V

    invoke-virtual {v2, v6}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    add-int/lit8 v3, v3, 0x1

    goto :goto_1

    :cond_1
    new-instance v1, Llyiahf/vczjk/ey6;

    const/4 v3, 0x0

    invoke-direct {v1, v2, v3}, Llyiahf/vczjk/ey6;-><init>(Ljava/util/List;Llyiahf/vczjk/hl1;)V

    iput-object v1, v0, Llyiahf/vczjk/nb9;->OooOooo:Llyiahf/vczjk/ey6;

    sget-object v2, Llyiahf/vczjk/fy6;->OooOOO0:Llyiahf/vczjk/fy6;

    invoke-virtual {v0, v1, v2}, Llyiahf/vczjk/nb9;->o00000Oo(Llyiahf/vczjk/ey6;Llyiahf/vczjk/fy6;)V

    sget-object v2, Llyiahf/vczjk/fy6;->OooOOO:Llyiahf/vczjk/fy6;

    invoke-virtual {v0, v1, v2}, Llyiahf/vczjk/nb9;->o00000Oo(Llyiahf/vczjk/ey6;Llyiahf/vczjk/fy6;)V

    sget-object v2, Llyiahf/vczjk/fy6;->OooOOOO:Llyiahf/vczjk/fy6;

    invoke-virtual {v0, v1, v2}, Llyiahf/vczjk/nb9;->o00000Oo(Llyiahf/vczjk/ey6;Llyiahf/vczjk/fy6;)V

    iput-object v3, v0, Llyiahf/vczjk/nb9;->Oooo0:Llyiahf/vczjk/ey6;

    return-void

    :cond_2
    add-int/lit8 v4, v4, 0x1

    goto :goto_0

    :cond_3
    :goto_2
    return-void
.end method

.method public final o00000OO(Llyiahf/vczjk/ze3;Llyiahf/vczjk/yo1;)Ljava/lang/Object;
    .locals 4

    new-instance v0, Llyiahf/vczjk/yp0;

    invoke-static {p2}, Llyiahf/vczjk/dn8;->ooOO(Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;

    move-result-object p2

    const/4 v1, 0x1

    invoke-direct {v0, v1, p2}, Llyiahf/vczjk/yp0;-><init>(ILlyiahf/vczjk/yo1;)V

    invoke-virtual {v0}, Llyiahf/vczjk/yp0;->OooOOoo()V

    new-instance p2, Llyiahf/vczjk/kb9;

    invoke-direct {p2, p0, v0}, Llyiahf/vczjk/kb9;-><init>(Llyiahf/vczjk/nb9;Llyiahf/vczjk/yp0;)V

    iget-object v1, p0, Llyiahf/vczjk/nb9;->Oooo00O:Llyiahf/vczjk/ws5;

    monitor-enter v1

    :try_start_0
    iget-object v2, p0, Llyiahf/vczjk/nb9;->Oooo000:Llyiahf/vczjk/ws5;

    invoke-virtual {v2, p2}, Llyiahf/vczjk/ws5;->OooO0O0(Ljava/lang/Object;)V

    new-instance v2, Llyiahf/vczjk/r48;

    invoke-static {p2, p2, p1}, Llyiahf/vczjk/dn8;->Oooo0o(Llyiahf/vczjk/yo1;Llyiahf/vczjk/yo1;Llyiahf/vczjk/ze3;)Llyiahf/vczjk/yo1;

    move-result-object p1

    invoke-static {p1}, Llyiahf/vczjk/dn8;->ooOO(Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;

    move-result-object p1

    sget-object v3, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    invoke-direct {v2, p1}, Llyiahf/vczjk/r48;-><init>(Llyiahf/vczjk/yo1;)V

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    invoke-virtual {v2, p1}, Llyiahf/vczjk/r48;->resumeWith(Ljava/lang/Object;)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    monitor-exit v1

    new-instance p1, Llyiahf/vczjk/lb9;

    invoke-direct {p1, p2}, Llyiahf/vczjk/lb9;-><init>(Llyiahf/vczjk/kb9;)V

    invoke-virtual {v0, p1}, Llyiahf/vczjk/yp0;->OooOo0(Llyiahf/vczjk/oe3;)V

    invoke-virtual {v0}, Llyiahf/vczjk/yp0;->OooOOo()Ljava/lang/Object;

    move-result-object p1

    return-object p1

    :catchall_0
    move-exception p1

    monitor-exit v1

    throw p1
.end method

.method public final o00000Oo(Llyiahf/vczjk/ey6;Llyiahf/vczjk/fy6;)V
    .locals 6

    iget-object v0, p0, Llyiahf/vczjk/nb9;->Oooo00O:Llyiahf/vczjk/ws5;

    monitor-enter v0

    :try_start_0
    iget-object v1, p0, Llyiahf/vczjk/nb9;->Oooo00o:Llyiahf/vczjk/ws5;

    iget-object v2, p0, Llyiahf/vczjk/nb9;->Oooo000:Llyiahf/vczjk/ws5;

    iget v3, v1, Llyiahf/vczjk/ws5;->OooOOOO:I

    invoke-virtual {v1, v3, v2}, Llyiahf/vczjk/ws5;->OooO0Oo(ILlyiahf/vczjk/ws5;)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_1

    monitor-exit v0

    :try_start_1
    invoke-virtual {p2}, Ljava/lang/Enum;->ordinal()I

    move-result v0

    const/4 v1, 0x0

    if-eqz v0, :cond_2

    const/4 v2, 0x1

    if-eq v0, v2, :cond_0

    const/4 v2, 0x2

    if-eq v0, v2, :cond_2

    goto :goto_2

    :cond_0
    iget-object v0, p0, Llyiahf/vczjk/nb9;->Oooo00o:Llyiahf/vczjk/ws5;

    iget v3, v0, Llyiahf/vczjk/ws5;->OooOOOO:I

    sub-int/2addr v3, v2

    iget-object v0, v0, Llyiahf/vczjk/ws5;->OooOOO0:[Ljava/lang/Object;

    array-length v2, v0

    if-ge v3, v2, :cond_4

    :goto_0
    if-ltz v3, :cond_4

    aget-object v2, v0, v3

    check-cast v2, Llyiahf/vczjk/kb9;

    iget-object v4, v2, Llyiahf/vczjk/kb9;->OooOOOo:Llyiahf/vczjk/fy6;

    if-ne p2, v4, :cond_1

    iget-object v4, v2, Llyiahf/vczjk/kb9;->OooOOOO:Llyiahf/vczjk/yp0;

    if-eqz v4, :cond_1

    iput-object v1, v2, Llyiahf/vczjk/kb9;->OooOOOO:Llyiahf/vczjk/yp0;

    invoke-virtual {v4, p1}, Llyiahf/vczjk/yp0;->resumeWith(Ljava/lang/Object;)V

    :cond_1
    add-int/lit8 v3, v3, -0x1

    goto :goto_0

    :catchall_0
    move-exception p1

    goto :goto_3

    :cond_2
    iget-object v0, p0, Llyiahf/vczjk/nb9;->Oooo00o:Llyiahf/vczjk/ws5;

    iget-object v2, v0, Llyiahf/vczjk/ws5;->OooOOO0:[Ljava/lang/Object;

    iget v0, v0, Llyiahf/vczjk/ws5;->OooOOOO:I

    const/4 v3, 0x0

    :goto_1
    if-ge v3, v0, :cond_4

    aget-object v4, v2, v3

    check-cast v4, Llyiahf/vczjk/kb9;

    iget-object v5, v4, Llyiahf/vczjk/kb9;->OooOOOo:Llyiahf/vczjk/fy6;

    if-ne p2, v5, :cond_3

    iget-object v5, v4, Llyiahf/vczjk/kb9;->OooOOOO:Llyiahf/vczjk/yp0;

    if-eqz v5, :cond_3

    iput-object v1, v4, Llyiahf/vczjk/kb9;->OooOOOO:Llyiahf/vczjk/yp0;

    invoke-virtual {v5, p1}, Llyiahf/vczjk/yp0;->resumeWith(Ljava/lang/Object;)V
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    :cond_3
    add-int/lit8 v3, v3, 0x1

    goto :goto_1

    :cond_4
    :goto_2
    iget-object p1, p0, Llyiahf/vczjk/nb9;->Oooo00o:Llyiahf/vczjk/ws5;

    invoke-virtual {p1}, Llyiahf/vczjk/ws5;->OooO0oO()V

    return-void

    :goto_3
    iget-object p2, p0, Llyiahf/vczjk/nb9;->Oooo00o:Llyiahf/vczjk/ws5;

    invoke-virtual {p2}, Llyiahf/vczjk/ws5;->OooO0oO()V

    throw p1

    :catchall_1
    move-exception p1

    monitor-exit v0

    throw p1
.end method

.method public final o00000o0()V
    .locals 4

    iget-object v0, p0, Llyiahf/vczjk/nb9;->OooOooO:Llyiahf/vczjk/r09;

    if-eqz v0, :cond_0

    new-instance v1, Llyiahf/vczjk/r23;

    const-string v2, "Pointer input was reset"

    const/4 v3, 0x4

    invoke-direct {v1, v2, v3}, Llyiahf/vczjk/r23;-><init>(Ljava/lang/String;I)V

    invoke-virtual {v0, v1}, Llyiahf/vczjk/k84;->OooOOoo(Ljava/util/concurrent/CancellationException;)V

    const/4 v0, 0x0

    iput-object v0, p0, Llyiahf/vczjk/nb9;->OooOooO:Llyiahf/vczjk/r09;

    :cond_0
    return-void
.end method

.method public final o000OOo()V
    .locals 0

    invoke-virtual {p0}, Llyiahf/vczjk/nb9;->o00000o0()V

    return-void
.end method

.method public final o000oOoO()F
    .locals 1

    invoke-static {p0}, Llyiahf/vczjk/yi4;->o00oO0o(Llyiahf/vczjk/l52;)Llyiahf/vczjk/ro4;

    move-result-object v0

    iget-object v0, v0, Llyiahf/vczjk/ro4;->Oooo0OO:Llyiahf/vczjk/f62;

    invoke-interface {v0}, Llyiahf/vczjk/f62;->o000oOoO()F

    move-result v0

    return v0
.end method

.method public final o00oO0O()V
    .locals 0

    invoke-virtual {p0}, Llyiahf/vczjk/nb9;->o00000o0()V

    return-void
.end method

.method public final ooOO(Llyiahf/vczjk/ey6;Llyiahf/vczjk/fy6;J)V
    .locals 3

    iput-wide p3, p0, Llyiahf/vczjk/nb9;->Oooo0O0:J

    sget-object p3, Llyiahf/vczjk/fy6;->OooOOO0:Llyiahf/vczjk/fy6;

    if-ne p2, p3, :cond_0

    iput-object p1, p0, Llyiahf/vczjk/nb9;->OooOooo:Llyiahf/vczjk/ey6;

    :cond_0
    iget-object p3, p0, Llyiahf/vczjk/nb9;->OooOooO:Llyiahf/vczjk/r09;

    const/4 p4, 0x0

    if-nez p3, :cond_1

    invoke-virtual {p0}, Llyiahf/vczjk/jl5;->o0OOO0o()Llyiahf/vczjk/xr1;

    move-result-object p3

    sget-object v0, Llyiahf/vczjk/as1;->OooOOOo:Llyiahf/vczjk/as1;

    new-instance v1, Llyiahf/vczjk/mb9;

    invoke-direct {v1, p0, p4}, Llyiahf/vczjk/mb9;-><init>(Llyiahf/vczjk/nb9;Llyiahf/vczjk/yo1;)V

    const/4 v2, 0x1

    invoke-static {p3, p4, v0, v1, v2}, Llyiahf/vczjk/os9;->Oooo0O0(Llyiahf/vczjk/xr1;Llyiahf/vczjk/or1;Llyiahf/vczjk/as1;Llyiahf/vczjk/ze3;I)Llyiahf/vczjk/r09;

    move-result-object p3

    iput-object p3, p0, Llyiahf/vczjk/nb9;->OooOooO:Llyiahf/vczjk/r09;

    :cond_1
    invoke-virtual {p0, p1, p2}, Llyiahf/vczjk/nb9;->o00000Oo(Llyiahf/vczjk/ey6;Llyiahf/vczjk/fy6;)V

    iget-object p2, p1, Llyiahf/vczjk/ey6;->OooO00o:Ljava/lang/Object;

    invoke-interface {p2}, Ljava/util/Collection;->size()I

    move-result p3

    const/4 v0, 0x0

    :goto_0
    if-ge v0, p3, :cond_3

    invoke-interface {p2, v0}, Ljava/util/List;->get(I)Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Llyiahf/vczjk/ky6;

    invoke-static {v1}, Llyiahf/vczjk/vl6;->OooOO0(Llyiahf/vczjk/ky6;)Z

    move-result v1

    if-nez v1, :cond_2

    goto :goto_1

    :cond_2
    add-int/lit8 v0, v0, 0x1

    goto :goto_0

    :cond_3
    move-object p1, p4

    :goto_1
    iput-object p1, p0, Llyiahf/vczjk/nb9;->Oooo0:Llyiahf/vczjk/ey6;

    return-void
.end method
