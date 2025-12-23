.class public final Llyiahf/vczjk/zr8;
.super Llyiahf/vczjk/eb9;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/bf3;


# instance fields
.field final synthetic $state:Llyiahf/vczjk/cs8;

.field synthetic J$0:J

.field label:I


# direct methods
.method public constructor <init>(Llyiahf/vczjk/cs8;Llyiahf/vczjk/yo1;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/zr8;->$state:Llyiahf/vczjk/cs8;

    const/4 p1, 0x3

    invoke-direct {p0, p1, p2}, Llyiahf/vczjk/eb9;-><init>(ILlyiahf/vczjk/yo1;)V

    return-void
.end method


# virtual methods
.method public final OooO0o0(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 2

    check-cast p1, Llyiahf/vczjk/l37;

    check-cast p2, Llyiahf/vczjk/p86;

    iget-wide p1, p2, Llyiahf/vczjk/p86;->OooO00o:J

    check-cast p3, Llyiahf/vczjk/yo1;

    new-instance v0, Llyiahf/vczjk/zr8;

    iget-object v1, p0, Llyiahf/vczjk/zr8;->$state:Llyiahf/vczjk/cs8;

    invoke-direct {v0, v1, p3}, Llyiahf/vczjk/zr8;-><init>(Llyiahf/vczjk/cs8;Llyiahf/vczjk/yo1;)V

    iput-wide p1, v0, Llyiahf/vczjk/zr8;->J$0:J

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    invoke-virtual {v0, p1}, Llyiahf/vczjk/zr8;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    return-object p1
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 4

    sget-object v0, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    iget v0, p0, Llyiahf/vczjk/zr8;->label:I

    if-nez v0, :cond_2

    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    iget-wide v0, p0, Llyiahf/vczjk/zr8;->J$0:J

    iget-object p1, p0, Llyiahf/vczjk/zr8;->$state:Llyiahf/vczjk/cs8;

    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    sget-object v2, Llyiahf/vczjk/nf6;->OooOOO0:Llyiahf/vczjk/nf6;

    iget-object v3, p1, Llyiahf/vczjk/cs8;->OooOO0o:Llyiahf/vczjk/nf6;

    if-ne v3, v2, :cond_0

    const-wide v2, 0xffffffffL

    and-long/2addr v0, v2

    long-to-int v0, v0

    invoke-static {v0}, Ljava/lang/Float;->intBitsToFloat(I)F

    move-result v0

    goto :goto_0

    :cond_0
    iget-boolean v2, p1, Llyiahf/vczjk/cs8;->OooO:Z

    const/16 v3, 0x20

    if-eqz v2, :cond_1

    iget-object v2, p1, Llyiahf/vczjk/cs8;->OooO0oO:Llyiahf/vczjk/qr5;

    check-cast v2, Llyiahf/vczjk/bw8;

    invoke-virtual {v2}, Llyiahf/vczjk/bw8;->OooOOoo()I

    move-result v2

    int-to-float v2, v2

    shr-long/2addr v0, v3

    long-to-int v0, v0

    invoke-static {v0}, Ljava/lang/Float;->intBitsToFloat(I)F

    move-result v0

    sub-float v0, v2, v0

    goto :goto_0

    :cond_1
    shr-long/2addr v0, v3

    long-to-int v0, v0

    invoke-static {v0}, Ljava/lang/Float;->intBitsToFloat(I)F

    move-result v0

    :goto_0
    iget-object v1, p1, Llyiahf/vczjk/cs8;->OooOOOO:Llyiahf/vczjk/lr5;

    check-cast v1, Llyiahf/vczjk/zv8;

    invoke-virtual {v1}, Llyiahf/vczjk/zv8;->OooOOoo()F

    move-result v1

    sub-float/2addr v0, v1

    iget-object p1, p1, Llyiahf/vczjk/cs8;->OooOOOo:Llyiahf/vczjk/lr5;

    check-cast p1, Llyiahf/vczjk/zv8;

    invoke-virtual {p1, v0}, Llyiahf/vczjk/zv8;->OooOo00(F)V

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1

    :cond_2
    new-instance p1, Ljava/lang/IllegalStateException;

    const-string v0, "call to \'resume\' before \'invoke\' with coroutine"

    invoke-direct {p1, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p1
.end method
