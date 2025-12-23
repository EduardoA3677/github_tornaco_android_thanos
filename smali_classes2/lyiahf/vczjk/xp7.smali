.class public final Llyiahf/vczjk/xp7;
.super Llyiahf/vczjk/eb9;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field final synthetic $state:Llyiahf/vczjk/fq7;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/fq7;"
        }
    .end annotation
.end field

.field private synthetic L$0:Ljava/lang/Object;

.field L$1:Ljava/lang/Object;

.field label:I


# direct methods
.method public constructor <init>(Llyiahf/vczjk/yo1;Llyiahf/vczjk/fq7;)V
    .locals 0

    iput-object p2, p0, Llyiahf/vczjk/xp7;->$state:Llyiahf/vczjk/fq7;

    const/4 p2, 0x2

    invoke-direct {p0, p2, p1}, Llyiahf/vczjk/eb9;-><init>(ILlyiahf/vczjk/yo1;)V

    return-void
.end method


# virtual methods
.method public final create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;
    .locals 2

    new-instance v0, Llyiahf/vczjk/xp7;

    iget-object v1, p0, Llyiahf/vczjk/xp7;->$state:Llyiahf/vczjk/fq7;

    invoke-direct {v0, p2, v1}, Llyiahf/vczjk/xp7;-><init>(Llyiahf/vczjk/yo1;Llyiahf/vczjk/fq7;)V

    iput-object p1, v0, Llyiahf/vczjk/xp7;->L$0:Ljava/lang/Object;

    return-object v0
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    check-cast p1, Llyiahf/vczjk/oy6;

    check-cast p2, Llyiahf/vczjk/yo1;

    invoke-virtual {p0, p1, p2}, Llyiahf/vczjk/xp7;->create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/xp7;

    sget-object p2, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    invoke-virtual {p1, p2}, Llyiahf/vczjk/xp7;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    return-object p1
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 14

    sget-object v0, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    iget v1, p0, Llyiahf/vczjk/xp7;->label:I

    sget-object v2, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    const/4 v3, 0x3

    const/4 v4, 0x2

    const/4 v5, 0x1

    const/4 v6, 0x0

    if-eqz v1, :cond_3

    if-eq v1, v5, :cond_2

    if-eq v1, v4, :cond_1

    if-ne v1, v3, :cond_0

    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    return-object v2

    :cond_0
    new-instance v0, Ljava/lang/IllegalStateException;

    const-string v1, "call to \'resume\' before \'invoke\' with coroutine"

    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw v0

    :cond_1
    iget-object v1, p0, Llyiahf/vczjk/xp7;->L$1:Ljava/lang/Object;

    check-cast v1, Llyiahf/vczjk/r19;

    iget-object v4, p0, Llyiahf/vczjk/xp7;->L$0:Ljava/lang/Object;

    check-cast v4, Llyiahf/vczjk/oy6;

    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    move-object v5, v1

    move-object v1, p1

    goto :goto_1

    :cond_2
    iget-object v1, p0, Llyiahf/vczjk/xp7;->L$0:Ljava/lang/Object;

    check-cast v1, Llyiahf/vczjk/oy6;

    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    move-object v5, p1

    goto :goto_0

    :cond_3
    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    iget-object v1, p0, Llyiahf/vczjk/xp7;->L$0:Ljava/lang/Object;

    check-cast v1, Llyiahf/vczjk/oy6;

    iget-object v7, p0, Llyiahf/vczjk/xp7;->$state:Llyiahf/vczjk/fq7;

    iget-object v7, v7, Llyiahf/vczjk/fq7;->OooO0o:Llyiahf/vczjk/jj0;

    iput-object v1, p0, Llyiahf/vczjk/xp7;->L$0:Ljava/lang/Object;

    iput v5, p0, Llyiahf/vczjk/xp7;->label:I

    invoke-virtual {v7, p0}, Llyiahf/vczjk/jj0;->OooO00o(Llyiahf/vczjk/eb9;)Ljava/lang/Object;

    move-result-object v5

    if-ne v5, v0, :cond_4

    goto :goto_3

    :cond_4
    :goto_0
    check-cast v5, Llyiahf/vczjk/r19;

    new-instance v7, Llyiahf/vczjk/wp7;

    invoke-direct {v7, v5, v6}, Llyiahf/vczjk/wp7;-><init>(Llyiahf/vczjk/r19;Llyiahf/vczjk/yo1;)V

    iput-object v1, p0, Llyiahf/vczjk/xp7;->L$0:Ljava/lang/Object;

    iput-object v5, p0, Llyiahf/vczjk/xp7;->L$1:Ljava/lang/Object;

    iput v4, p0, Llyiahf/vczjk/xp7;->label:I

    move-object v4, v1

    check-cast v4, Llyiahf/vczjk/nb9;

    invoke-virtual {v4, v7, p0}, Llyiahf/vczjk/nb9;->o00000OO(Llyiahf/vczjk/ze3;Llyiahf/vczjk/yo1;)Ljava/lang/Object;

    move-result-object v1

    if-ne v1, v0, :cond_5

    goto :goto_3

    :cond_5
    :goto_1
    check-cast v1, Llyiahf/vczjk/ky6;

    if-eqz v1, :cond_7

    iget-object v7, p0, Llyiahf/vczjk/xp7;->$state:Llyiahf/vczjk/fq7;

    const/16 v8, 0x20

    iget-wide v9, v1, Llyiahf/vczjk/ky6;->OooO0OO:J

    shr-long v11, v9, v8

    long-to-int v8, v11

    invoke-static {v8}, Ljava/lang/Float;->intBitsToFloat(I)F

    move-result v8

    float-to-int v8, v8

    const-wide v11, 0xffffffffL

    and-long/2addr v9, v11

    long-to-int v9, v9

    invoke-static {v9}, Ljava/lang/Float;->intBitsToFloat(I)F

    move-result v9

    float-to-int v9, v9

    invoke-virtual {v7, v8, v9}, Llyiahf/vczjk/fq7;->OooOOoo(II)Z

    move-result v7

    if-eqz v7, :cond_7

    invoke-virtual {v5}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    iget-object v5, p0, Llyiahf/vczjk/xp7;->$state:Llyiahf/vczjk/fq7;

    new-instance v10, Llyiahf/vczjk/up7;

    const/4 v7, 0x0

    invoke-direct {v10, v5, v7}, Llyiahf/vczjk/up7;-><init>(Llyiahf/vczjk/fq7;I)V

    new-instance v11, Llyiahf/vczjk/up7;

    const/4 v7, 0x1

    invoke-direct {v11, v5, v7}, Llyiahf/vczjk/up7;-><init>(Llyiahf/vczjk/fq7;I)V

    new-instance v12, Llyiahf/vczjk/vp7;

    const/4 v7, 0x0

    invoke-direct {v12, v5, v7}, Llyiahf/vczjk/vp7;-><init>(Llyiahf/vczjk/fq7;I)V

    iput-object v6, p0, Llyiahf/vczjk/xp7;->L$0:Ljava/lang/Object;

    iput-object v6, p0, Llyiahf/vczjk/xp7;->L$1:Ljava/lang/Object;

    iput v3, p0, Llyiahf/vczjk/xp7;->label:I

    new-instance v7, Llyiahf/vczjk/tp7;

    const/4 v13, 0x0

    iget-wide v8, v1, Llyiahf/vczjk/ky6;->OooO00o:J

    invoke-direct/range {v7 .. v13}, Llyiahf/vczjk/tp7;-><init>(JLlyiahf/vczjk/le3;Llyiahf/vczjk/le3;Llyiahf/vczjk/ze3;Llyiahf/vczjk/yo1;)V

    check-cast v4, Llyiahf/vczjk/nb9;

    invoke-virtual {v4, v7, p0}, Llyiahf/vczjk/nb9;->o00000OO(Llyiahf/vczjk/ze3;Llyiahf/vczjk/yo1;)Ljava/lang/Object;

    move-result-object v1

    if-ne v1, v0, :cond_6

    goto :goto_2

    :cond_6
    move-object v1, v2

    :goto_2
    if-ne v1, v0, :cond_7

    :goto_3
    return-object v0

    :cond_7
    return-object v2
.end method
