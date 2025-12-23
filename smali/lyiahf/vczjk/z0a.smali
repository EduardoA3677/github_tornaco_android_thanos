.class public final Llyiahf/vczjk/z0a;
.super Llyiahf/vczjk/eb9;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field final synthetic $connection:Llyiahf/vczjk/ay9;

.field final synthetic $tablesToSync:[Llyiahf/vczjk/g86;

.field I$0:I

.field I$1:I

.field I$2:I

.field L$0:Ljava/lang/Object;

.field L$1:Ljava/lang/Object;

.field L$2:Ljava/lang/Object;

.field label:I

.field final synthetic this$0:Llyiahf/vczjk/b1a;


# direct methods
.method public constructor <init>([Llyiahf/vczjk/g86;Llyiahf/vczjk/b1a;Llyiahf/vczjk/ay9;Llyiahf/vczjk/yo1;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/z0a;->$tablesToSync:[Llyiahf/vczjk/g86;

    iput-object p2, p0, Llyiahf/vczjk/z0a;->this$0:Llyiahf/vczjk/b1a;

    iput-object p3, p0, Llyiahf/vczjk/z0a;->$connection:Llyiahf/vczjk/ay9;

    const/4 p1, 0x2

    invoke-direct {p0, p1, p4}, Llyiahf/vczjk/eb9;-><init>(ILlyiahf/vczjk/yo1;)V

    return-void
.end method


# virtual methods
.method public final create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;
    .locals 3

    new-instance p1, Llyiahf/vczjk/z0a;

    iget-object v0, p0, Llyiahf/vczjk/z0a;->$tablesToSync:[Llyiahf/vczjk/g86;

    iget-object v1, p0, Llyiahf/vczjk/z0a;->this$0:Llyiahf/vczjk/b1a;

    iget-object v2, p0, Llyiahf/vczjk/z0a;->$connection:Llyiahf/vczjk/ay9;

    invoke-direct {p1, v0, v1, v2, p2}, Llyiahf/vczjk/z0a;-><init>([Llyiahf/vczjk/g86;Llyiahf/vczjk/b1a;Llyiahf/vczjk/ay9;Llyiahf/vczjk/yo1;)V

    return-object p1
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    check-cast p1, Llyiahf/vczjk/iz6;

    check-cast p2, Llyiahf/vczjk/yo1;

    invoke-virtual {p0, p1, p2}, Llyiahf/vczjk/z0a;->create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/z0a;

    sget-object p2, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    invoke-virtual {p1, p2}, Llyiahf/vczjk/z0a;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    return-object p1
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 10

    sget-object v0, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    iget v1, p0, Llyiahf/vczjk/z0a;->label:I

    const/4 v2, 0x1

    const/4 v3, 0x2

    if-eqz v1, :cond_2

    if-eq v1, v2, :cond_0

    if-ne v1, v3, :cond_1

    :cond_0
    iget v1, p0, Llyiahf/vczjk/z0a;->I$2:I

    iget v4, p0, Llyiahf/vczjk/z0a;->I$1:I

    iget v5, p0, Llyiahf/vczjk/z0a;->I$0:I

    iget-object v6, p0, Llyiahf/vczjk/z0a;->L$2:Ljava/lang/Object;

    check-cast v6, Llyiahf/vczjk/ay9;

    iget-object v7, p0, Llyiahf/vczjk/z0a;->L$1:Ljava/lang/Object;

    check-cast v7, Llyiahf/vczjk/b1a;

    iget-object v8, p0, Llyiahf/vczjk/z0a;->L$0:Ljava/lang/Object;

    check-cast v8, [Llyiahf/vczjk/g86;

    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    goto :goto_1

    :cond_1
    new-instance p1, Ljava/lang/IllegalStateException;

    const-string v0, "call to \'resume\' before \'invoke\' with coroutine"

    invoke-direct {p1, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p1

    :cond_2
    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    iget-object p1, p0, Llyiahf/vczjk/z0a;->$tablesToSync:[Llyiahf/vczjk/g86;

    iget-object v1, p0, Llyiahf/vczjk/z0a;->this$0:Llyiahf/vczjk/b1a;

    iget-object v4, p0, Llyiahf/vczjk/z0a;->$connection:Llyiahf/vczjk/ay9;

    array-length v5, p1

    const/4 v6, 0x0

    move-object v8, p1

    move-object v7, v1

    move-object p1, v4

    move v1, v5

    move v4, v6

    :goto_0
    if-ge v4, v1, :cond_7

    aget-object v5, v8, v4

    add-int/lit8 v9, v6, 0x1

    invoke-virtual {v5}, Ljava/lang/Enum;->ordinal()I

    move-result v5

    if-eqz v5, :cond_6

    if-eq v5, v2, :cond_5

    if-ne v5, v3, :cond_4

    iput-object v8, p0, Llyiahf/vczjk/z0a;->L$0:Ljava/lang/Object;

    iput-object v7, p0, Llyiahf/vczjk/z0a;->L$1:Ljava/lang/Object;

    iput-object p1, p0, Llyiahf/vczjk/z0a;->L$2:Ljava/lang/Object;

    iput v9, p0, Llyiahf/vczjk/z0a;->I$0:I

    iput v4, p0, Llyiahf/vczjk/z0a;->I$1:I

    iput v1, p0, Llyiahf/vczjk/z0a;->I$2:I

    iput v3, p0, Llyiahf/vczjk/z0a;->label:I

    invoke-static {v7, p1, v6, p0}, Llyiahf/vczjk/b1a;->OooO0Oo(Llyiahf/vczjk/b1a;Llyiahf/vczjk/ay9;ILlyiahf/vczjk/zo1;)Ljava/lang/Object;

    move-result-object v5

    if-ne v5, v0, :cond_3

    goto :goto_2

    :cond_3
    move-object v6, p1

    move v5, v9

    :goto_1
    move-object p1, v6

    move v6, v5

    goto :goto_3

    :cond_4
    new-instance p1, Llyiahf/vczjk/k61;

    invoke-direct {p1}, Ljava/lang/RuntimeException;-><init>()V

    throw p1

    :cond_5
    iput-object v8, p0, Llyiahf/vczjk/z0a;->L$0:Ljava/lang/Object;

    iput-object v7, p0, Llyiahf/vczjk/z0a;->L$1:Ljava/lang/Object;

    iput-object p1, p0, Llyiahf/vczjk/z0a;->L$2:Ljava/lang/Object;

    iput v9, p0, Llyiahf/vczjk/z0a;->I$0:I

    iput v4, p0, Llyiahf/vczjk/z0a;->I$1:I

    iput v1, p0, Llyiahf/vczjk/z0a;->I$2:I

    iput v2, p0, Llyiahf/vczjk/z0a;->label:I

    invoke-static {v7, p1, v6, p0}, Llyiahf/vczjk/b1a;->OooO0OO(Llyiahf/vczjk/b1a;Llyiahf/vczjk/ay9;ILlyiahf/vczjk/zo1;)Ljava/lang/Object;

    move-result-object v5

    if-ne v5, v0, :cond_3

    :goto_2
    return-object v0

    :cond_6
    move v6, v9

    :goto_3
    add-int/2addr v4, v2

    goto :goto_0

    :cond_7
    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method
