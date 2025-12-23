.class public final Llyiahf/vczjk/n93;
.super Llyiahf/vczjk/m52;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ne8;
.implements Llyiahf/vczjk/gi3;
.implements Llyiahf/vczjk/ug1;
.implements Llyiahf/vczjk/l86;
.implements Llyiahf/vczjk/c0a;


# static fields
.field public static final Oooo0O0:Llyiahf/vczjk/xj0;


# instance fields
.field public OooOoo:Llyiahf/vczjk/rr5;

.field public final OooOooO:Llyiahf/vczjk/o00000;

.field public OooOooo:Llyiahf/vczjk/g83;

.field public Oooo0:Llyiahf/vczjk/i93;

.field public Oooo000:Llyiahf/vczjk/eu4;

.field public Oooo00O:Llyiahf/vczjk/v16;

.field public final Oooo00o:Llyiahf/vczjk/d93;


# direct methods
.method static constructor <clinit>()V
    .locals 2

    new-instance v0, Llyiahf/vczjk/xj0;

    const/16 v1, 0x11

    invoke-direct {v0, v1}, Llyiahf/vczjk/xj0;-><init>(I)V

    sput-object v0, Llyiahf/vczjk/n93;->Oooo0O0:Llyiahf/vczjk/xj0;

    return-void
.end method

.method public constructor <init>(Llyiahf/vczjk/rr5;ILlyiahf/vczjk/o00000;)V
    .locals 8

    invoke-direct {p0}, Llyiahf/vczjk/m52;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/n93;->OooOoo:Llyiahf/vczjk/rr5;

    iput-object p3, p0, Llyiahf/vczjk/n93;->OooOooO:Llyiahf/vczjk/o00000;

    new-instance v0, Llyiahf/vczjk/fa;

    const-string v5, "onFocusStateChange(Landroidx/compose/ui/focus/FocusState;Landroidx/compose/ui/focus/FocusState;)V"

    const/4 v6, 0x0

    const/4 v1, 0x2

    const-class v3, Llyiahf/vczjk/n93;

    const-string v4, "onFocusStateChange"

    const/4 v7, 0x1

    move-object v2, p0

    invoke-direct/range {v0 .. v7}, Llyiahf/vczjk/fa;-><init>(ILjava/lang/Object;Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;II)V

    new-instance p1, Llyiahf/vczjk/d93;

    const/4 p3, 0x4

    invoke-direct {p1, p2, v0, p3}, Llyiahf/vczjk/d93;-><init>(ILlyiahf/vczjk/fa;I)V

    invoke-virtual {p0, p1}, Llyiahf/vczjk/m52;->o00000OO(Llyiahf/vczjk/l52;)Llyiahf/vczjk/l52;

    iput-object p1, v2, Llyiahf/vczjk/n93;->Oooo00o:Llyiahf/vczjk/d93;

    return-void
.end method


# virtual methods
.method public final OooOO0O()Ljava/lang/Object;
    .locals 1

    sget-object v0, Llyiahf/vczjk/n93;->Oooo0O0:Llyiahf/vczjk/xj0;

    return-object v0
.end method

.method public final OooOoO0(Llyiahf/vczjk/v16;)V
    .locals 1

    iput-object p1, p0, Llyiahf/vczjk/n93;->Oooo00O:Llyiahf/vczjk/v16;

    iget-object v0, p0, Llyiahf/vczjk/n93;->Oooo00o:Llyiahf/vczjk/d93;

    invoke-virtual {v0}, Llyiahf/vczjk/d93;->o00000o0()Llyiahf/vczjk/a93;

    move-result-object v0

    invoke-virtual {v0}, Llyiahf/vczjk/a93;->OooO00o()Z

    move-result v0

    if-nez v0, :cond_0

    goto :goto_0

    :cond_0
    invoke-virtual {p1}, Llyiahf/vczjk/v16;->o000OO()Llyiahf/vczjk/jl5;

    move-result-object p1

    iget-boolean p1, p1, Llyiahf/vczjk/jl5;->OooOoO:Z

    if-eqz p1, :cond_1

    iget-object p1, p0, Llyiahf/vczjk/n93;->Oooo00O:Llyiahf/vczjk/v16;

    if-eqz p1, :cond_2

    invoke-virtual {p1}, Llyiahf/vczjk/v16;->o000OO()Llyiahf/vczjk/jl5;

    move-result-object p1

    iget-boolean p1, p1, Llyiahf/vczjk/jl5;->OooOoO:Z

    if-eqz p1, :cond_2

    invoke-virtual {p0}, Llyiahf/vczjk/n93;->o00000oO()Llyiahf/vczjk/o93;

    move-result-object p1

    if-eqz p1, :cond_2

    iget-object v0, p0, Llyiahf/vczjk/n93;->Oooo00O:Llyiahf/vczjk/v16;

    invoke-virtual {p1, v0}, Llyiahf/vczjk/o93;->o00000OO(Llyiahf/vczjk/xn4;)V

    return-void

    :cond_1
    invoke-virtual {p0}, Llyiahf/vczjk/n93;->o00000oO()Llyiahf/vczjk/o93;

    move-result-object p1

    if-eqz p1, :cond_2

    const/4 v0, 0x0

    invoke-virtual {p1, v0}, Llyiahf/vczjk/o93;->o00000OO(Llyiahf/vczjk/xn4;)V

    :cond_2
    :goto_0
    return-void
.end method

.method public final OooooO0(Llyiahf/vczjk/af8;)V
    .locals 4

    iget-object v0, p0, Llyiahf/vczjk/n93;->Oooo00o:Llyiahf/vczjk/d93;

    invoke-virtual {v0}, Llyiahf/vczjk/d93;->o00000o0()Llyiahf/vczjk/a93;

    move-result-object v0

    invoke-virtual {v0}, Llyiahf/vczjk/a93;->OooO00o()Z

    move-result v0

    sget-object v1, Llyiahf/vczjk/ye8;->OooO00o:[Llyiahf/vczjk/th4;

    sget-object v1, Llyiahf/vczjk/ve8;->OooOO0O:Llyiahf/vczjk/ze8;

    sget-object v2, Llyiahf/vczjk/ye8;->OooO00o:[Llyiahf/vczjk/th4;

    const/4 v3, 0x4

    aget-object v2, v2, v3

    invoke-static {v0}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    move-result-object v0

    invoke-virtual {v1, p1, v0}, Llyiahf/vczjk/ze8;->OooO00o(Llyiahf/vczjk/af8;Ljava/lang/Object;)V

    iget-object v0, p0, Llyiahf/vczjk/n93;->Oooo0:Llyiahf/vczjk/i93;

    if-nez v0, :cond_0

    new-instance v0, Llyiahf/vczjk/i93;

    invoke-direct {v0, p0}, Llyiahf/vczjk/i93;-><init>(Llyiahf/vczjk/n93;)V

    iput-object v0, p0, Llyiahf/vczjk/n93;->Oooo0:Llyiahf/vczjk/i93;

    :cond_0
    iget-object v0, p0, Llyiahf/vczjk/n93;->Oooo0:Llyiahf/vczjk/i93;

    sget-object v1, Llyiahf/vczjk/ie8;->OooOo0O:Llyiahf/vczjk/ze8;

    new-instance v2, Llyiahf/vczjk/o0O00O;

    const/4 v3, 0x0

    invoke-direct {v2, v3, v0}, Llyiahf/vczjk/o0O00O;-><init>(Ljava/lang/String;Llyiahf/vczjk/cf3;)V

    check-cast p1, Llyiahf/vczjk/je8;

    invoke-virtual {p1, v1, v2}, Llyiahf/vczjk/je8;->OooO0oo(Llyiahf/vczjk/ze8;Ljava/lang/Object;)V

    return-void
.end method

.method public final Oooooo()V
    .locals 2

    new-instance v0, Llyiahf/vczjk/hl7;

    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    new-instance v1, Llyiahf/vczjk/m93;

    invoke-direct {v1, v0, p0}, Llyiahf/vczjk/m93;-><init>(Llyiahf/vczjk/hl7;Llyiahf/vczjk/n93;)V

    invoke-static {p0, v1}, Llyiahf/vczjk/bua;->Oooo000(Llyiahf/vczjk/jl5;Llyiahf/vczjk/le3;)V

    iget-object v0, v0, Llyiahf/vczjk/hl7;->element:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/eu4;

    iget-object v1, p0, Llyiahf/vczjk/n93;->Oooo00o:Llyiahf/vczjk/d93;

    invoke-virtual {v1}, Llyiahf/vczjk/d93;->o00000o0()Llyiahf/vczjk/a93;

    move-result-object v1

    invoke-virtual {v1}, Llyiahf/vczjk/a93;->OooO00o()Z

    move-result v1

    if-eqz v1, :cond_2

    iget-object v1, p0, Llyiahf/vczjk/n93;->Oooo000:Llyiahf/vczjk/eu4;

    if-eqz v1, :cond_0

    invoke-virtual {v1}, Llyiahf/vczjk/eu4;->OooO0O0()V

    :cond_0
    if-eqz v0, :cond_1

    invoke-virtual {v0}, Llyiahf/vczjk/eu4;->OooO00o()Llyiahf/vczjk/eu4;

    goto :goto_0

    :cond_1
    const/4 v0, 0x0

    :goto_0
    iput-object v0, p0, Llyiahf/vczjk/n93;->Oooo000:Llyiahf/vczjk/eu4;

    :cond_2
    return-void
.end method

.method public final o000000()V
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/n93;->Oooo000:Llyiahf/vczjk/eu4;

    if-eqz v0, :cond_0

    invoke-virtual {v0}, Llyiahf/vczjk/eu4;->OooO0O0()V

    :cond_0
    const/4 v0, 0x0

    iput-object v0, p0, Llyiahf/vczjk/n93;->Oooo000:Llyiahf/vczjk/eu4;

    return-void
.end method

.method public final o00000oO()Llyiahf/vczjk/o93;
    .locals 11

    iget-boolean v0, p0, Llyiahf/vczjk/jl5;->OooOoO:Z

    const/4 v1, 0x0

    if-eqz v0, :cond_c

    sget-object v0, Llyiahf/vczjk/o93;->OooOoo0:Llyiahf/vczjk/uk2;

    iget-object v2, p0, Llyiahf/vczjk/jl5;->OooOOO0:Llyiahf/vczjk/jl5;

    iget-boolean v2, v2, Llyiahf/vczjk/jl5;->OooOoO:Z

    if-nez v2, :cond_0

    const-string v2, "visitAncestors called on an unattached node"

    invoke-static {v2}, Llyiahf/vczjk/pz3;->OooO0O0(Ljava/lang/String;)V

    :cond_0
    iget-object v2, p0, Llyiahf/vczjk/jl5;->OooOOO0:Llyiahf/vczjk/jl5;

    iget-object v2, v2, Llyiahf/vczjk/jl5;->OooOOo0:Llyiahf/vczjk/jl5;

    invoke-static {p0}, Llyiahf/vczjk/yi4;->o00oO0o(Llyiahf/vczjk/l52;)Llyiahf/vczjk/ro4;

    move-result-object v3

    :goto_0
    if-eqz v3, :cond_b

    iget-object v4, v3, Llyiahf/vczjk/ro4;->OoooO0:Llyiahf/vczjk/jb0;

    iget-object v4, v4, Llyiahf/vczjk/jb0;->OooO0o:Ljava/lang/Object;

    check-cast v4, Llyiahf/vczjk/jl5;

    iget v4, v4, Llyiahf/vczjk/jl5;->OooOOOo:I

    const/high16 v5, 0x40000

    and-int/2addr v4, v5

    if-eqz v4, :cond_9

    :goto_1
    if-eqz v2, :cond_9

    iget v4, v2, Llyiahf/vczjk/jl5;->OooOOOO:I

    and-int/2addr v4, v5

    if-eqz v4, :cond_8

    move-object v6, v1

    move-object v4, v2

    :goto_2
    if-eqz v4, :cond_8

    instance-of v7, v4, Llyiahf/vczjk/c0a;

    if-eqz v7, :cond_1

    check-cast v4, Llyiahf/vczjk/c0a;

    invoke-interface {v4}, Llyiahf/vczjk/c0a;->OooOO0O()Ljava/lang/Object;

    move-result-object v7

    invoke-virtual {v0, v7}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    move-result v7

    if-eqz v7, :cond_7

    goto :goto_5

    :cond_1
    iget v7, v4, Llyiahf/vczjk/jl5;->OooOOOO:I

    and-int/2addr v7, v5

    if-eqz v7, :cond_7

    instance-of v7, v4, Llyiahf/vczjk/m52;

    if-eqz v7, :cond_7

    move-object v7, v4

    check-cast v7, Llyiahf/vczjk/m52;

    iget-object v7, v7, Llyiahf/vczjk/m52;->OooOoo0:Llyiahf/vczjk/jl5;

    const/4 v8, 0x0

    :goto_3
    const/4 v9, 0x1

    if-eqz v7, :cond_6

    iget v10, v7, Llyiahf/vczjk/jl5;->OooOOOO:I

    and-int/2addr v10, v5

    if-eqz v10, :cond_5

    add-int/lit8 v8, v8, 0x1

    if-ne v8, v9, :cond_2

    move-object v4, v7

    goto :goto_4

    :cond_2
    if-nez v6, :cond_3

    new-instance v6, Llyiahf/vczjk/ws5;

    const/16 v9, 0x10

    new-array v9, v9, [Llyiahf/vczjk/jl5;

    invoke-direct {v6, v9}, Llyiahf/vczjk/ws5;-><init>([Ljava/lang/Object;)V

    :cond_3
    if-eqz v4, :cond_4

    invoke-virtual {v6, v4}, Llyiahf/vczjk/ws5;->OooO0O0(Ljava/lang/Object;)V

    move-object v4, v1

    :cond_4
    invoke-virtual {v6, v7}, Llyiahf/vczjk/ws5;->OooO0O0(Ljava/lang/Object;)V

    :cond_5
    :goto_4
    iget-object v7, v7, Llyiahf/vczjk/jl5;->OooOOo:Llyiahf/vczjk/jl5;

    goto :goto_3

    :cond_6
    if-ne v8, v9, :cond_7

    goto :goto_2

    :cond_7
    invoke-static {v6}, Llyiahf/vczjk/yi4;->OooOo0(Llyiahf/vczjk/ws5;)Llyiahf/vczjk/jl5;

    move-result-object v4

    goto :goto_2

    :cond_8
    iget-object v2, v2, Llyiahf/vczjk/jl5;->OooOOo0:Llyiahf/vczjk/jl5;

    goto :goto_1

    :cond_9
    invoke-virtual {v3}, Llyiahf/vczjk/ro4;->OooOo0O()Llyiahf/vczjk/ro4;

    move-result-object v3

    if-eqz v3, :cond_a

    iget-object v2, v3, Llyiahf/vczjk/ro4;->OoooO0:Llyiahf/vczjk/jb0;

    if-eqz v2, :cond_a

    iget-object v2, v2, Llyiahf/vczjk/jb0;->OooO0o0:Ljava/lang/Object;

    check-cast v2, Llyiahf/vczjk/cf9;

    goto :goto_0

    :cond_a
    move-object v2, v1

    goto :goto_0

    :cond_b
    move-object v4, v1

    :goto_5
    instance-of v0, v4, Llyiahf/vczjk/o93;

    if-eqz v0, :cond_c

    check-cast v4, Llyiahf/vczjk/o93;

    return-object v4

    :cond_c
    return-object v1
.end method

.method public final o00000oo(Llyiahf/vczjk/rr5;)V
    .locals 3

    iget-object v0, p0, Llyiahf/vczjk/n93;->OooOoo:Llyiahf/vczjk/rr5;

    invoke-static {v0, p1}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v0

    if-nez v0, :cond_1

    iget-object v0, p0, Llyiahf/vczjk/n93;->OooOoo:Llyiahf/vczjk/rr5;

    if-eqz v0, :cond_0

    iget-object v1, p0, Llyiahf/vczjk/n93;->OooOooo:Llyiahf/vczjk/g83;

    if-eqz v1, :cond_0

    new-instance v2, Llyiahf/vczjk/h83;

    invoke-direct {v2, v1}, Llyiahf/vczjk/h83;-><init>(Llyiahf/vczjk/g83;)V

    check-cast v0, Llyiahf/vczjk/sr5;

    invoke-virtual {v0, v2}, Llyiahf/vczjk/sr5;->OooO0OO(Llyiahf/vczjk/j24;)Z

    :cond_0
    const/4 v0, 0x0

    iput-object v0, p0, Llyiahf/vczjk/n93;->OooOooo:Llyiahf/vczjk/g83;

    iput-object p1, p0, Llyiahf/vczjk/n93;->OooOoo:Llyiahf/vczjk/rr5;

    :cond_1
    return-void
.end method

.method public final o0000Ooo(Llyiahf/vczjk/rr5;Llyiahf/vczjk/j24;)V
    .locals 4

    iget-boolean v0, p0, Llyiahf/vczjk/jl5;->OooOoO:Z

    if-eqz v0, :cond_1

    invoke-virtual {p0}, Llyiahf/vczjk/jl5;->o0OOO0o()Llyiahf/vczjk/xr1;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/to1;

    sget-object v1, Llyiahf/vczjk/ws7;->OooOOo0:Llyiahf/vczjk/ws7;

    iget-object v0, v0, Llyiahf/vczjk/to1;->OooOOO0:Llyiahf/vczjk/or1;

    invoke-interface {v0, v1}, Llyiahf/vczjk/or1;->OooOo(Llyiahf/vczjk/nr1;)Llyiahf/vczjk/mr1;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/v74;

    const/4 v1, 0x0

    if-eqz v0, :cond_0

    new-instance v2, Llyiahf/vczjk/k93;

    invoke-direct {v2, p1, p2}, Llyiahf/vczjk/k93;-><init>(Llyiahf/vczjk/rr5;Llyiahf/vczjk/j24;)V

    invoke-interface {v0, v2}, Llyiahf/vczjk/v74;->OoooO00(Llyiahf/vczjk/oe3;)Llyiahf/vczjk/sc2;

    move-result-object v0

    goto :goto_0

    :cond_0
    move-object v0, v1

    :goto_0
    invoke-virtual {p0}, Llyiahf/vczjk/jl5;->o0OOO0o()Llyiahf/vczjk/xr1;

    move-result-object v2

    new-instance v3, Llyiahf/vczjk/j93;

    invoke-direct {v3, p1, p2, v0, v1}, Llyiahf/vczjk/j93;-><init>(Llyiahf/vczjk/rr5;Llyiahf/vczjk/j24;Llyiahf/vczjk/sc2;Llyiahf/vczjk/yo1;)V

    const/4 p1, 0x3

    invoke-static {v2, v1, v1, v3, p1}, Llyiahf/vczjk/os9;->Oooo0O0(Llyiahf/vczjk/xr1;Llyiahf/vczjk/or1;Llyiahf/vczjk/as1;Llyiahf/vczjk/ze3;I)Llyiahf/vczjk/r09;

    return-void

    :cond_1
    check-cast p1, Llyiahf/vczjk/sr5;

    invoke-virtual {p1, p2}, Llyiahf/vczjk/sr5;->OooO0OO(Llyiahf/vczjk/j24;)Z

    return-void
.end method
