.class public final Llyiahf/vczjk/bt4;
.super Ljava/lang/Object;
.source "SourceFile"


# static fields
.field public static final OooOOoo:J

.field public static final synthetic OooOo00:I


# instance fields
.field public final OooO:Llyiahf/vczjk/qs5;

.field public final OooO00o:Llyiahf/vczjk/xr1;

.field public final OooO0O0:Llyiahf/vczjk/ij3;

.field public final OooO0OO:Llyiahf/vczjk/et4;

.field public OooO0Oo:Llyiahf/vczjk/wz8;

.field public OooO0o:Llyiahf/vczjk/wz8;

.field public OooO0o0:Llyiahf/vczjk/wz8;

.field public OooO0oO:Z

.field public final OooO0oo:Llyiahf/vczjk/qs5;

.field public final OooOO0:Llyiahf/vczjk/qs5;

.field public final OooOO0O:Llyiahf/vczjk/qs5;

.field public OooOO0o:J

.field public OooOOO:Llyiahf/vczjk/kj3;

.field public OooOOO0:J

.field public final OooOOOO:Llyiahf/vczjk/gi;

.field public final OooOOOo:Llyiahf/vczjk/gi;

.field public OooOOo:J

.field public final OooOOo0:Llyiahf/vczjk/qs5;


# direct methods
.method static constructor <clinit>()V
    .locals 6

    const v0, 0x7fffffff

    int-to-long v0, v0

    const/16 v2, 0x20

    shl-long v2, v0, v2

    const-wide v4, 0xffffffffL

    and-long/2addr v0, v4

    or-long/2addr v0, v2

    sput-wide v0, Llyiahf/vczjk/bt4;->OooOOoo:J

    return-void
.end method

.method public constructor <init>(Llyiahf/vczjk/xr1;Llyiahf/vczjk/ij3;Llyiahf/vczjk/et4;)V
    .locals 6

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/bt4;->OooO00o:Llyiahf/vczjk/xr1;

    iput-object p2, p0, Llyiahf/vczjk/bt4;->OooO0O0:Llyiahf/vczjk/ij3;

    iput-object p3, p0, Llyiahf/vczjk/bt4;->OooO0OO:Llyiahf/vczjk/et4;

    sget-object p1, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    invoke-static {p1}, Landroidx/compose/runtime/OooO0o;->OooOO0(Ljava/lang/Object;)Llyiahf/vczjk/qs5;

    move-result-object p3

    iput-object p3, p0, Llyiahf/vczjk/bt4;->OooO0oo:Llyiahf/vczjk/qs5;

    invoke-static {p1}, Landroidx/compose/runtime/OooO0o;->OooOO0(Ljava/lang/Object;)Llyiahf/vczjk/qs5;

    move-result-object p3

    iput-object p3, p0, Llyiahf/vczjk/bt4;->OooO:Llyiahf/vczjk/qs5;

    invoke-static {p1}, Landroidx/compose/runtime/OooO0o;->OooOO0(Ljava/lang/Object;)Llyiahf/vczjk/qs5;

    move-result-object p3

    iput-object p3, p0, Llyiahf/vczjk/bt4;->OooOO0:Llyiahf/vczjk/qs5;

    invoke-static {p1}, Landroidx/compose/runtime/OooO0o;->OooOO0(Ljava/lang/Object;)Llyiahf/vczjk/qs5;

    move-result-object p1

    iput-object p1, p0, Llyiahf/vczjk/bt4;->OooOO0O:Llyiahf/vczjk/qs5;

    sget-wide v0, Llyiahf/vczjk/bt4;->OooOOoo:J

    iput-wide v0, p0, Llyiahf/vczjk/bt4;->OooOO0o:J

    const-wide/16 v2, 0x0

    iput-wide v2, p0, Llyiahf/vczjk/bt4;->OooOOO0:J

    const/4 p1, 0x0

    if-eqz p2, :cond_0

    invoke-interface {p2}, Llyiahf/vczjk/ij3;->OooO0O0()Llyiahf/vczjk/kj3;

    move-result-object p2

    goto :goto_0

    :cond_0
    move-object p2, p1

    :goto_0
    iput-object p2, p0, Llyiahf/vczjk/bt4;->OooOOO:Llyiahf/vczjk/kj3;

    new-instance p2, Llyiahf/vczjk/gi;

    new-instance p3, Llyiahf/vczjk/u14;

    invoke-direct {p3, v2, v3}, Llyiahf/vczjk/u14;-><init>(J)V

    sget-object v4, Llyiahf/vczjk/gda;->OooO0oO:Llyiahf/vczjk/n1a;

    const/16 v5, 0xc

    invoke-direct {p2, p3, v4, p1, v5}, Llyiahf/vczjk/gi;-><init>(Ljava/lang/Object;Llyiahf/vczjk/n1a;Ljava/lang/Object;I)V

    iput-object p2, p0, Llyiahf/vczjk/bt4;->OooOOOO:Llyiahf/vczjk/gi;

    new-instance p2, Llyiahf/vczjk/gi;

    const/high16 p3, 0x3f800000    # 1.0f

    invoke-static {p3}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    move-result-object p3

    sget-object v4, Llyiahf/vczjk/gda;->OooO00o:Llyiahf/vczjk/n1a;

    invoke-direct {p2, p3, v4, p1, v5}, Llyiahf/vczjk/gi;-><init>(Ljava/lang/Object;Llyiahf/vczjk/n1a;Ljava/lang/Object;I)V

    iput-object p2, p0, Llyiahf/vczjk/bt4;->OooOOOo:Llyiahf/vczjk/gi;

    new-instance p1, Llyiahf/vczjk/u14;

    invoke-direct {p1, v2, v3}, Llyiahf/vczjk/u14;-><init>(J)V

    invoke-static {p1}, Landroidx/compose/runtime/OooO0o;->OooOO0(Ljava/lang/Object;)Llyiahf/vczjk/qs5;

    move-result-object p1

    iput-object p1, p0, Llyiahf/vczjk/bt4;->OooOOo0:Llyiahf/vczjk/qs5;

    iput-wide v0, p0, Llyiahf/vczjk/bt4;->OooOOo:J

    return-void
.end method


# virtual methods
.method public final OooO00o()V
    .locals 9

    iget-object v4, p0, Llyiahf/vczjk/bt4;->OooOOO:Llyiahf/vczjk/kj3;

    iget-object v3, p0, Llyiahf/vczjk/bt4;->OooO0Oo:Llyiahf/vczjk/wz8;

    iget-object v0, p0, Llyiahf/vczjk/bt4;->OooO:Llyiahf/vczjk/qs5;

    check-cast v0, Llyiahf/vczjk/fw8;

    invoke-virtual {v0}, Llyiahf/vczjk/fw8;->getValue()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Ljava/lang/Boolean;

    invoke-virtual {v0}, Ljava/lang/Boolean;->booleanValue()Z

    move-result v0

    iget-object v6, p0, Llyiahf/vczjk/bt4;->OooO00o:Llyiahf/vczjk/xr1;

    const/4 v7, 0x3

    const/4 v8, 0x0

    if-nez v0, :cond_0

    if-eqz v3, :cond_0

    if-nez v4, :cond_1

    :cond_0
    move-object v2, p0

    goto :goto_0

    :cond_1
    const/4 v0, 0x1

    invoke-virtual {p0, v0}, Llyiahf/vczjk/bt4;->OooO0Oo(Z)V

    invoke-virtual {p0}, Llyiahf/vczjk/bt4;->OooO0O0()Z

    move-result v0

    xor-int/lit8 v1, v0, 0x1

    if-nez v0, :cond_2

    const/4 v0, 0x0

    invoke-virtual {v4, v0}, Llyiahf/vczjk/kj3;->OooO0o(F)V

    :cond_2
    new-instance v0, Llyiahf/vczjk/ss4;

    const/4 v5, 0x0

    move-object v2, p0

    invoke-direct/range {v0 .. v5}, Llyiahf/vczjk/ss4;-><init>(ZLlyiahf/vczjk/bt4;Llyiahf/vczjk/p13;Llyiahf/vczjk/kj3;Llyiahf/vczjk/yo1;)V

    invoke-static {v6, v8, v8, v0, v7}, Llyiahf/vczjk/os9;->Oooo0O0(Llyiahf/vczjk/xr1;Llyiahf/vczjk/or1;Llyiahf/vczjk/as1;Llyiahf/vczjk/ze3;I)Llyiahf/vczjk/r09;

    return-void

    :goto_0
    invoke-virtual {p0}, Llyiahf/vczjk/bt4;->OooO0O0()Z

    move-result v0

    if-eqz v0, :cond_4

    if-nez v4, :cond_3

    goto :goto_1

    :cond_3
    const/high16 v0, 0x3f800000    # 1.0f

    invoke-virtual {v4, v0}, Llyiahf/vczjk/kj3;->OooO0o(F)V

    :goto_1
    new-instance v0, Llyiahf/vczjk/qs4;

    invoke-direct {v0, p0, v8}, Llyiahf/vczjk/qs4;-><init>(Llyiahf/vczjk/bt4;Llyiahf/vczjk/yo1;)V

    invoke-static {v6, v8, v8, v0, v7}, Llyiahf/vczjk/os9;->Oooo0O0(Llyiahf/vczjk/xr1;Llyiahf/vczjk/or1;Llyiahf/vczjk/as1;Llyiahf/vczjk/ze3;I)Llyiahf/vczjk/r09;

    :cond_4
    return-void
.end method

.method public final OooO0O0()Z
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/bt4;->OooOO0:Llyiahf/vczjk/qs5;

    check-cast v0, Llyiahf/vczjk/fw8;

    invoke-virtual {v0}, Llyiahf/vczjk/fw8;->getValue()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Ljava/lang/Boolean;

    invoke-virtual {v0}, Ljava/lang/Boolean;->booleanValue()Z

    move-result v0

    return v0
.end method

.method public final OooO0OO()V
    .locals 5

    iget-object v0, p0, Llyiahf/vczjk/bt4;->OooO0oo:Llyiahf/vczjk/qs5;

    check-cast v0, Llyiahf/vczjk/fw8;

    invoke-virtual {v0}, Llyiahf/vczjk/fw8;->getValue()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Ljava/lang/Boolean;

    invoke-virtual {v0}, Ljava/lang/Boolean;->booleanValue()Z

    move-result v0

    iget-object v1, p0, Llyiahf/vczjk/bt4;->OooO00o:Llyiahf/vczjk/xr1;

    const/4 v2, 0x3

    const/4 v3, 0x0

    const/4 v4, 0x0

    if-eqz v0, :cond_0

    invoke-virtual {p0, v4}, Llyiahf/vczjk/bt4;->OooO0o(Z)V

    new-instance v0, Llyiahf/vczjk/ys4;

    invoke-direct {v0, p0, v3}, Llyiahf/vczjk/ys4;-><init>(Llyiahf/vczjk/bt4;Llyiahf/vczjk/yo1;)V

    invoke-static {v1, v3, v3, v0, v2}, Llyiahf/vczjk/os9;->Oooo0O0(Llyiahf/vczjk/xr1;Llyiahf/vczjk/or1;Llyiahf/vczjk/as1;Llyiahf/vczjk/ze3;I)Llyiahf/vczjk/r09;

    :cond_0
    iget-object v0, p0, Llyiahf/vczjk/bt4;->OooO:Llyiahf/vczjk/qs5;

    check-cast v0, Llyiahf/vczjk/fw8;

    invoke-virtual {v0}, Llyiahf/vczjk/fw8;->getValue()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Ljava/lang/Boolean;

    invoke-virtual {v0}, Ljava/lang/Boolean;->booleanValue()Z

    move-result v0

    if-eqz v0, :cond_1

    invoke-virtual {p0, v4}, Llyiahf/vczjk/bt4;->OooO0Oo(Z)V

    new-instance v0, Llyiahf/vczjk/zs4;

    invoke-direct {v0, p0, v3}, Llyiahf/vczjk/zs4;-><init>(Llyiahf/vczjk/bt4;Llyiahf/vczjk/yo1;)V

    invoke-static {v1, v3, v3, v0, v2}, Llyiahf/vczjk/os9;->Oooo0O0(Llyiahf/vczjk/xr1;Llyiahf/vczjk/or1;Llyiahf/vczjk/as1;Llyiahf/vczjk/ze3;I)Llyiahf/vczjk/r09;

    :cond_1
    invoke-virtual {p0}, Llyiahf/vczjk/bt4;->OooO0O0()Z

    move-result v0

    if-eqz v0, :cond_2

    invoke-virtual {p0, v4}, Llyiahf/vczjk/bt4;->OooO0o0(Z)V

    new-instance v0, Llyiahf/vczjk/at4;

    invoke-direct {v0, p0, v3}, Llyiahf/vczjk/at4;-><init>(Llyiahf/vczjk/bt4;Llyiahf/vczjk/yo1;)V

    invoke-static {v1, v3, v3, v0, v2}, Llyiahf/vczjk/os9;->Oooo0O0(Llyiahf/vczjk/xr1;Llyiahf/vczjk/or1;Llyiahf/vczjk/as1;Llyiahf/vczjk/ze3;I)Llyiahf/vczjk/r09;

    :cond_2
    iput-boolean v4, p0, Llyiahf/vczjk/bt4;->OooO0oO:Z

    const-wide/16 v0, 0x0

    invoke-virtual {p0, v0, v1}, Llyiahf/vczjk/bt4;->OooO0oO(J)V

    sget-wide v0, Llyiahf/vczjk/bt4;->OooOOoo:J

    iput-wide v0, p0, Llyiahf/vczjk/bt4;->OooOO0o:J

    iget-object v0, p0, Llyiahf/vczjk/bt4;->OooOOO:Llyiahf/vczjk/kj3;

    if-eqz v0, :cond_3

    iget-object v1, p0, Llyiahf/vczjk/bt4;->OooO0O0:Llyiahf/vczjk/ij3;

    if-eqz v1, :cond_3

    invoke-interface {v1, v0}, Llyiahf/vczjk/ij3;->OooO00o(Llyiahf/vczjk/kj3;)V

    :cond_3
    iput-object v3, p0, Llyiahf/vczjk/bt4;->OooOOO:Llyiahf/vczjk/kj3;

    iput-object v3, p0, Llyiahf/vczjk/bt4;->OooO0Oo:Llyiahf/vczjk/wz8;

    iput-object v3, p0, Llyiahf/vczjk/bt4;->OooO0o:Llyiahf/vczjk/wz8;

    iput-object v3, p0, Llyiahf/vczjk/bt4;->OooO0o0:Llyiahf/vczjk/wz8;

    return-void
.end method

.method public final OooO0Oo(Z)V
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/bt4;->OooO:Llyiahf/vczjk/qs5;

    invoke-static {p1}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    move-result-object p1

    check-cast v0, Llyiahf/vczjk/fw8;

    invoke-virtual {v0, p1}, Llyiahf/vczjk/fw8;->setValue(Ljava/lang/Object;)V

    return-void
.end method

.method public final OooO0o(Z)V
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/bt4;->OooO0oo:Llyiahf/vczjk/qs5;

    invoke-static {p1}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    move-result-object p1

    check-cast v0, Llyiahf/vczjk/fw8;

    invoke-virtual {v0, p1}, Llyiahf/vczjk/fw8;->setValue(Ljava/lang/Object;)V

    return-void
.end method

.method public final OooO0o0(Z)V
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/bt4;->OooOO0:Llyiahf/vczjk/qs5;

    invoke-static {p1}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    move-result-object p1

    check-cast v0, Llyiahf/vczjk/fw8;

    invoke-virtual {v0, p1}, Llyiahf/vczjk/fw8;->setValue(Ljava/lang/Object;)V

    return-void
.end method

.method public final OooO0oO(J)V
    .locals 2

    iget-object v0, p0, Llyiahf/vczjk/bt4;->OooOOo0:Llyiahf/vczjk/qs5;

    new-instance v1, Llyiahf/vczjk/u14;

    invoke-direct {v1, p1, p2}, Llyiahf/vczjk/u14;-><init>(J)V

    check-cast v0, Llyiahf/vczjk/fw8;

    invoke-virtual {v0, v1}, Llyiahf/vczjk/fw8;->setValue(Ljava/lang/Object;)V

    return-void
.end method
