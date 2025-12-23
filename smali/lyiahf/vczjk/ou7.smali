.class public final Llyiahf/vczjk/ou7;
.super Llyiahf/vczjk/eb9;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field final synthetic $hasForeignKeys:Z

.field final synthetic $tableNames:[Ljava/lang/String;

.field I$0:I

.field I$1:I

.field private synthetic L$0:Ljava/lang/Object;

.field L$1:Ljava/lang/Object;

.field label:I


# direct methods
.method public constructor <init>(Z[Ljava/lang/String;Llyiahf/vczjk/yo1;)V
    .locals 0

    iput-boolean p1, p0, Llyiahf/vczjk/ou7;->$hasForeignKeys:Z

    iput-object p2, p0, Llyiahf/vczjk/ou7;->$tableNames:[Ljava/lang/String;

    const/4 p1, 0x2

    invoke-direct {p0, p1, p3}, Llyiahf/vczjk/eb9;-><init>(ILlyiahf/vczjk/yo1;)V

    return-void
.end method


# virtual methods
.method public final create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;
    .locals 3

    new-instance v0, Llyiahf/vczjk/ou7;

    iget-boolean v1, p0, Llyiahf/vczjk/ou7;->$hasForeignKeys:Z

    iget-object v2, p0, Llyiahf/vczjk/ou7;->$tableNames:[Ljava/lang/String;

    invoke-direct {v0, v1, v2, p2}, Llyiahf/vczjk/ou7;-><init>(Z[Ljava/lang/String;Llyiahf/vczjk/yo1;)V

    iput-object p1, v0, Llyiahf/vczjk/ou7;->L$0:Ljava/lang/Object;

    return-object v0
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    check-cast p1, Llyiahf/vczjk/iz6;

    check-cast p2, Llyiahf/vczjk/yo1;

    invoke-virtual {p0, p1, p2}, Llyiahf/vczjk/ou7;->create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/ou7;

    sget-object p2, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    invoke-virtual {p1, p2}, Llyiahf/vczjk/ou7;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    return-object p1
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 9

    sget-object v0, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    iget v1, p0, Llyiahf/vczjk/ou7;->label:I

    const/4 v2, 0x2

    const/4 v3, 0x1

    if-eqz v1, :cond_2

    if-eq v1, v3, :cond_1

    if-ne v1, v2, :cond_0

    iget v1, p0, Llyiahf/vczjk/ou7;->I$1:I

    iget v4, p0, Llyiahf/vczjk/ou7;->I$0:I

    iget-object v5, p0, Llyiahf/vczjk/ou7;->L$1:Ljava/lang/Object;

    check-cast v5, [Ljava/lang/String;

    iget-object v6, p0, Llyiahf/vczjk/ou7;->L$0:Ljava/lang/Object;

    check-cast v6, Llyiahf/vczjk/iz6;

    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    goto :goto_3

    :cond_0
    new-instance p1, Ljava/lang/IllegalStateException;

    const-string v0, "call to \'resume\' before \'invoke\' with coroutine"

    invoke-direct {p1, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p1

    :cond_1
    iget-object v1, p0, Llyiahf/vczjk/ou7;->L$0:Ljava/lang/Object;

    check-cast v1, Llyiahf/vczjk/iz6;

    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    goto :goto_0

    :cond_2
    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    iget-object p1, p0, Llyiahf/vczjk/ou7;->L$0:Ljava/lang/Object;

    move-object v1, p1

    check-cast v1, Llyiahf/vczjk/iz6;

    iget-boolean p1, p0, Llyiahf/vczjk/ou7;->$hasForeignKeys:Z

    if-eqz p1, :cond_3

    iput-object v1, p0, Llyiahf/vczjk/ou7;->L$0:Ljava/lang/Object;

    iput v3, p0, Llyiahf/vczjk/ou7;->label:I

    const-string p1, "PRAGMA defer_foreign_keys = TRUE"

    invoke-static {v1, p1, p0}, Llyiahf/vczjk/rl6;->OooOOO0(Llyiahf/vczjk/gz6;Ljava/lang/String;Llyiahf/vczjk/zo1;)Ljava/lang/Object;

    move-result-object p1

    if-ne p1, v0, :cond_3

    goto :goto_2

    :cond_3
    :goto_0
    iget-object p1, p0, Llyiahf/vczjk/ou7;->$tableNames:[Ljava/lang/String;

    array-length v4, p1

    const/4 v5, 0x0

    move-object v6, v1

    move v1, v4

    move v4, v5

    move-object v5, p1

    :goto_1
    if-ge v4, v1, :cond_5

    aget-object p1, v5, v4

    new-instance v7, Ljava/lang/StringBuilder;

    const-string v8, "DELETE FROM `"

    invoke-direct {v7, v8}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {v7, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    const/16 p1, 0x60

    invoke-virtual {v7, p1}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    invoke-virtual {v7}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object p1

    iput-object v6, p0, Llyiahf/vczjk/ou7;->L$0:Ljava/lang/Object;

    iput-object v5, p0, Llyiahf/vczjk/ou7;->L$1:Ljava/lang/Object;

    iput v4, p0, Llyiahf/vczjk/ou7;->I$0:I

    iput v1, p0, Llyiahf/vczjk/ou7;->I$1:I

    iput v2, p0, Llyiahf/vczjk/ou7;->label:I

    invoke-static {v6, p1, p0}, Llyiahf/vczjk/rl6;->OooOOO0(Llyiahf/vczjk/gz6;Ljava/lang/String;Llyiahf/vczjk/zo1;)Ljava/lang/Object;

    move-result-object p1

    if-ne p1, v0, :cond_4

    :goto_2
    return-object v0

    :cond_4
    :goto_3
    add-int/2addr v4, v3

    goto :goto_1

    :cond_5
    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method
