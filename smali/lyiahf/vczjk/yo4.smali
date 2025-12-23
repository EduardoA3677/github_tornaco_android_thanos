.class public final Llyiahf/vczjk/yo4;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/mf5;


# instance fields
.field public final synthetic OooO00o:I

.field public final synthetic OooO0O0:I

.field public final synthetic OooO0OO:Ljava/util/Map;

.field public final synthetic OooO0Oo:Llyiahf/vczjk/ow;

.field public final synthetic OooO0o:Llyiahf/vczjk/fp4;

.field public final synthetic OooO0o0:Llyiahf/vczjk/zo4;

.field public final synthetic OooO0oO:Llyiahf/vczjk/oe3;


# direct methods
.method public constructor <init>(IILjava/util/Map;Llyiahf/vczjk/ow;Llyiahf/vczjk/zo4;Llyiahf/vczjk/fp4;Llyiahf/vczjk/oe3;)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput p1, p0, Llyiahf/vczjk/yo4;->OooO00o:I

    iput p2, p0, Llyiahf/vczjk/yo4;->OooO0O0:I

    iput-object p3, p0, Llyiahf/vczjk/yo4;->OooO0OO:Ljava/util/Map;

    iput-object p4, p0, Llyiahf/vczjk/yo4;->OooO0Oo:Llyiahf/vczjk/ow;

    iput-object p5, p0, Llyiahf/vczjk/yo4;->OooO0o0:Llyiahf/vczjk/zo4;

    iput-object p6, p0, Llyiahf/vczjk/yo4;->OooO0o:Llyiahf/vczjk/fp4;

    iput-object p7, p0, Llyiahf/vczjk/yo4;->OooO0oO:Llyiahf/vczjk/oe3;

    return-void
.end method


# virtual methods
.method public final OooO00o()Ljava/util/Map;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/yo4;->OooO0OO:Ljava/util/Map;

    return-object v0
.end method

.method public final OooO0O0()V
    .locals 3

    iget-object v0, p0, Llyiahf/vczjk/yo4;->OooO0o0:Llyiahf/vczjk/zo4;

    invoke-virtual {v0}, Llyiahf/vczjk/zo4;->OoooOo0()Z

    move-result v0

    iget-object v1, p0, Llyiahf/vczjk/yo4;->OooO0oO:Llyiahf/vczjk/oe3;

    iget-object v2, p0, Llyiahf/vczjk/yo4;->OooO0o:Llyiahf/vczjk/fp4;

    if-eqz v0, :cond_0

    iget-object v0, v2, Llyiahf/vczjk/fp4;->OooOOO0:Llyiahf/vczjk/ro4;

    iget-object v0, v0, Llyiahf/vczjk/ro4;->OoooO0:Llyiahf/vczjk/jb0;

    iget-object v0, v0, Llyiahf/vczjk/jb0;->OooO0OO:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/b04;

    iget-object v0, v0, Llyiahf/vczjk/b04;->OoooOoo:Llyiahf/vczjk/a04;

    if-eqz v0, :cond_0

    iget-object v0, v0, Llyiahf/vczjk/o65;->OooOo0:Llyiahf/vczjk/p65;

    invoke-interface {v1, v0}, Llyiahf/vczjk/oe3;->OooO0o(Ljava/lang/Object;)Ljava/lang/Object;

    return-void

    :cond_0
    iget-object v0, v2, Llyiahf/vczjk/fp4;->OooOOO0:Llyiahf/vczjk/ro4;

    iget-object v0, v0, Llyiahf/vczjk/ro4;->OoooO0:Llyiahf/vczjk/jb0;

    iget-object v0, v0, Llyiahf/vczjk/jb0;->OooO0OO:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/b04;

    iget-object v0, v0, Llyiahf/vczjk/o65;->OooOo0:Llyiahf/vczjk/p65;

    invoke-interface {v1, v0}, Llyiahf/vczjk/oe3;->OooO0o(Ljava/lang/Object;)Ljava/lang/Object;

    return-void
.end method

.method public final OooO0OO()Llyiahf/vczjk/oe3;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/yo4;->OooO0Oo:Llyiahf/vczjk/ow;

    return-object v0
.end method

.method public final getHeight()I
    .locals 1

    iget v0, p0, Llyiahf/vczjk/yo4;->OooO0O0:I

    return v0
.end method

.method public final getWidth()I
    .locals 1

    iget v0, p0, Llyiahf/vczjk/yo4;->OooO00o:I

    return v0
.end method
