.class public final Llyiahf/vczjk/or3;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/cx;
.implements Llyiahf/vczjk/f14;
.implements Llyiahf/vczjk/aea;


# instance fields
.field public OooOOO:I

.field public final OooOOO0:I

.field public final OooOOOO:Ljava/lang/Object;


# direct methods
.method public constructor <init>()V
    .locals 1

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    const/16 v0, 0x100

    new-array v0, v0, [Llyiahf/vczjk/or3;

    iput-object v0, p0, Llyiahf/vczjk/or3;->OooOOOO:Ljava/lang/Object;

    const/4 v0, 0x0

    iput v0, p0, Llyiahf/vczjk/or3;->OooOOO0:I

    iput v0, p0, Llyiahf/vczjk/or3;->OooOOO:I

    return-void
.end method

.method public constructor <init>(II)V
    .locals 1

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    const/4 v0, 0x0

    iput-object v0, p0, Llyiahf/vczjk/or3;->OooOOOO:Ljava/lang/Object;

    iput p1, p0, Llyiahf/vczjk/or3;->OooOOO0:I

    and-int/lit8 p1, p2, 0x7

    if-nez p1, :cond_0

    const/16 p1, 0x8

    :cond_0
    iput p1, p0, Llyiahf/vczjk/or3;->OooOOO:I

    return-void
.end method

.method public constructor <init>(IILlyiahf/vczjk/ik2;)V
    .locals 2

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput p1, p0, Llyiahf/vczjk/or3;->OooOOO0:I

    iput p2, p0, Llyiahf/vczjk/or3;->OooOOO:I

    new-instance v0, Llyiahf/vczjk/pb7;

    new-instance v1, Llyiahf/vczjk/c33;

    invoke-direct {v1, p1, p2, p3}, Llyiahf/vczjk/c33;-><init>(IILlyiahf/vczjk/ik2;)V

    invoke-direct {v0, v1}, Llyiahf/vczjk/pb7;-><init>(Llyiahf/vczjk/t23;)V

    iput-object v0, p0, Llyiahf/vczjk/or3;->OooOOOO:Ljava/lang/Object;

    return-void
.end method

.method public constructor <init>(IILlyiahf/vczjk/le3;)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput p1, p0, Llyiahf/vczjk/or3;->OooOOO0:I

    iput p2, p0, Llyiahf/vczjk/or3;->OooOOO:I

    check-cast p3, Llyiahf/vczjk/rm4;

    iput-object p3, p0, Llyiahf/vczjk/or3;->OooOOOO:Ljava/lang/Object;

    return-void
.end method

.method public constructor <init>(Llyiahf/vczjk/cx;I)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/or3;->OooOOOO:Ljava/lang/Object;

    iput p2, p0, Llyiahf/vczjk/or3;->OooOOO0:I

    return-void
.end method

.method public constructor <init>([ZII)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/or3;->OooOOOO:Ljava/lang/Object;

    iput p2, p0, Llyiahf/vczjk/or3;->OooOOO0:I

    iput p3, p0, Llyiahf/vczjk/or3;->OooOOO:I

    return-void
.end method


# virtual methods
.method public OooO(III)V
    .locals 1

    iget v0, p0, Llyiahf/vczjk/or3;->OooOOO:I

    if-nez v0, :cond_0

    iget v0, p0, Llyiahf/vczjk/or3;->OooOOO0:I

    goto :goto_0

    :cond_0
    const/4 v0, 0x0

    :goto_0
    add-int/2addr p1, v0

    add-int/2addr p2, v0

    iget-object v0, p0, Llyiahf/vczjk/or3;->OooOOOO:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/cx;

    invoke-interface {v0, p1, p2, p3}, Llyiahf/vczjk/cx;->OooO(III)V

    return-void
.end method

.method public OooO0O0(ILjava/lang/Object;)V
    .locals 1

    iget v0, p0, Llyiahf/vczjk/or3;->OooOOO:I

    if-nez v0, :cond_0

    iget v0, p0, Llyiahf/vczjk/or3;->OooOOO0:I

    goto :goto_0

    :cond_0
    const/4 v0, 0x0

    :goto_0
    add-int/2addr p1, v0

    iget-object v0, p0, Llyiahf/vczjk/or3;->OooOOOO:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/cx;

    invoke-interface {v0, p1, p2}, Llyiahf/vczjk/cx;->OooO0O0(ILjava/lang/Object;)V

    return-void
.end method

.method public OooO0OO(Ljava/lang/Object;)V
    .locals 1

    iget v0, p0, Llyiahf/vczjk/or3;->OooOOO:I

    add-int/lit8 v0, v0, 0x1

    iput v0, p0, Llyiahf/vczjk/or3;->OooOOO:I

    iget-object v0, p0, Llyiahf/vczjk/or3;->OooOOOO:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/cx;

    invoke-interface {v0, p1}, Llyiahf/vczjk/cx;->OooO0OO(Ljava/lang/Object;)V

    return-void
.end method

.method public OooO0Oo(Llyiahf/vczjk/ww6;)V
    .locals 0

    return-void
.end method

.method public OooO0oo(JLlyiahf/vczjk/dm;Llyiahf/vczjk/dm;Llyiahf/vczjk/dm;)Llyiahf/vczjk/dm;
    .locals 7

    iget-object v0, p0, Llyiahf/vczjk/or3;->OooOOOO:Ljava/lang/Object;

    move-object v1, v0

    check-cast v1, Llyiahf/vczjk/pb7;

    move-wide v2, p1

    move-object v4, p3

    move-object v5, p4

    move-object v6, p5

    invoke-virtual/range {v1 .. v6}, Llyiahf/vczjk/pb7;->OooO0oo(JLlyiahf/vczjk/dm;Llyiahf/vczjk/dm;Llyiahf/vczjk/dm;)Llyiahf/vczjk/dm;

    move-result-object p1

    return-object p1
.end method

.method public OooOO0(II)V
    .locals 1

    iget v0, p0, Llyiahf/vczjk/or3;->OooOOO:I

    if-nez v0, :cond_0

    iget v0, p0, Llyiahf/vczjk/or3;->OooOOO0:I

    goto :goto_0

    :cond_0
    const/4 v0, 0x0

    :goto_0
    add-int/2addr p1, v0

    iget-object v0, p0, Llyiahf/vczjk/or3;->OooOOOO:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/cx;

    invoke-interface {v0, p1, p2}, Llyiahf/vczjk/cx;->OooOO0(II)V

    return-void
.end method

.method public OooOO0O(Llyiahf/vczjk/vw6;)V
    .locals 5

    iget-object v0, p1, Llyiahf/vczjk/g14;->OooOOO0:Llyiahf/vczjk/dv7;

    iget v0, v0, Llyiahf/vczjk/dv7;->OooO00o:I

    const/4 v1, 0x3

    if-ne v0, v1, :cond_1

    iget-object v0, p1, Llyiahf/vczjk/nt1;->OooOOo0:Llyiahf/vczjk/hj1;

    check-cast v0, Llyiahf/vczjk/pt1;

    iget v0, v0, Llyiahf/vczjk/rt1;->OooOOO0:I

    iget-object v1, p0, Llyiahf/vczjk/or3;->OooOOOO:Ljava/lang/Object;

    check-cast v1, [Z

    const/4 v2, 0x0

    aget-boolean v3, v1, v2

    if-eqz v3, :cond_0

    iget v3, p0, Llyiahf/vczjk/or3;->OooOOO0:I

    iget v4, p0, Llyiahf/vczjk/or3;->OooOOO:I

    sub-int/2addr v3, v4

    add-int/2addr v3, v0

    iget-object p1, p1, Llyiahf/vczjk/g14;->OooOOOO:Llyiahf/vczjk/sn7;

    iget p1, p1, Llyiahf/vczjk/sn7;->OooOOO0:I

    if-ne v3, p1, :cond_0

    const/4 p1, 0x1

    goto :goto_0

    :cond_0
    move p1, v2

    :goto_0
    aput-boolean p1, v1, v2

    :cond_1
    return-void
.end method

.method public OooOO0o(JLlyiahf/vczjk/dm;Llyiahf/vczjk/dm;Llyiahf/vczjk/dm;)Llyiahf/vczjk/dm;
    .locals 7

    iget-object v0, p0, Llyiahf/vczjk/or3;->OooOOOO:Ljava/lang/Object;

    move-object v1, v0

    check-cast v1, Llyiahf/vczjk/pb7;

    move-wide v2, p1

    move-object v4, p3

    move-object v5, p4

    move-object v6, p5

    invoke-virtual/range {v1 .. v6}, Llyiahf/vczjk/pb7;->OooOO0o(JLlyiahf/vczjk/dm;Llyiahf/vczjk/dm;Llyiahf/vczjk/dm;)Llyiahf/vczjk/dm;

    move-result-object p1

    return-object p1
.end method

.method public OooOOO(ILjava/lang/Object;)V
    .locals 1

    iget v0, p0, Llyiahf/vczjk/or3;->OooOOO:I

    if-nez v0, :cond_0

    iget v0, p0, Llyiahf/vczjk/or3;->OooOOO0:I

    goto :goto_0

    :cond_0
    const/4 v0, 0x0

    :goto_0
    add-int/2addr p1, v0

    iget-object v0, p0, Llyiahf/vczjk/or3;->OooOOOO:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/cx;

    invoke-interface {v0, p1, p2}, Llyiahf/vczjk/cx;->OooOOO(ILjava/lang/Object;)V

    return-void
.end method

.method public OooOOO0()V
    .locals 1

    iget v0, p0, Llyiahf/vczjk/or3;->OooOOO:I

    if-lez v0, :cond_0

    const/4 v0, 0x1

    goto :goto_0

    :cond_0
    const/4 v0, 0x0

    :goto_0
    if-nez v0, :cond_1

    const-string v0, "OffsetApplier up called with no corresponding down"

    invoke-static {v0}, Llyiahf/vczjk/ag1;->OooO0OO(Ljava/lang/String;)V

    :cond_1
    iget v0, p0, Llyiahf/vczjk/or3;->OooOOO:I

    add-int/lit8 v0, v0, -0x1

    iput v0, p0, Llyiahf/vczjk/or3;->OooOOO:I

    iget-object v0, p0, Llyiahf/vczjk/or3;->OooOOOO:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/cx;

    invoke-interface {v0}, Llyiahf/vczjk/cx;->OooOOO0()V

    return-void
.end method

.method public OooOOOO()Ljava/lang/Object;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/or3;->OooOOOO:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/cx;

    invoke-interface {v0}, Llyiahf/vczjk/cx;->OooOOOO()Ljava/lang/Object;

    move-result-object v0

    return-object v0
.end method

.method public OooOOOo()I
    .locals 1

    iget v0, p0, Llyiahf/vczjk/or3;->OooOOO:I

    return v0
.end method

.method public OooOOo()I
    .locals 1

    iget v0, p0, Llyiahf/vczjk/or3;->OooOOO0:I

    return v0
.end method

.method public OooOOo0(Llyiahf/vczjk/lr9;)V
    .locals 0

    return-void
.end method

.method public OooOOoo(Llyiahf/vczjk/mr9;)V
    .locals 0

    return-void
.end method
