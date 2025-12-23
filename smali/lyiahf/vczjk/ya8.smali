.class public final Llyiahf/vczjk/ya8;
.super Llyiahf/vczjk/eb9;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field final synthetic $available:J

.field final synthetic $result:Llyiahf/vczjk/gl7;

.field J$0:J

.field private synthetic L$0:Ljava/lang/Object;

.field L$1:Ljava/lang/Object;

.field L$2:Ljava/lang/Object;

.field label:I

.field final synthetic this$0:Llyiahf/vczjk/db8;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/db8;Llyiahf/vczjk/gl7;JLlyiahf/vczjk/yo1;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/ya8;->this$0:Llyiahf/vczjk/db8;

    iput-object p2, p0, Llyiahf/vczjk/ya8;->$result:Llyiahf/vczjk/gl7;

    iput-wide p3, p0, Llyiahf/vczjk/ya8;->$available:J

    const/4 p1, 0x2

    invoke-direct {p0, p1, p5}, Llyiahf/vczjk/eb9;-><init>(ILlyiahf/vczjk/yo1;)V

    return-void
.end method


# virtual methods
.method public final create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;
    .locals 6

    new-instance v0, Llyiahf/vczjk/ya8;

    iget-object v1, p0, Llyiahf/vczjk/ya8;->this$0:Llyiahf/vczjk/db8;

    iget-object v2, p0, Llyiahf/vczjk/ya8;->$result:Llyiahf/vczjk/gl7;

    iget-wide v3, p0, Llyiahf/vczjk/ya8;->$available:J

    move-object v5, p2

    invoke-direct/range {v0 .. v5}, Llyiahf/vczjk/ya8;-><init>(Llyiahf/vczjk/db8;Llyiahf/vczjk/gl7;JLlyiahf/vczjk/yo1;)V

    iput-object p1, v0, Llyiahf/vczjk/ya8;->L$0:Ljava/lang/Object;

    return-object v0
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    check-cast p1, Llyiahf/vczjk/lz5;

    check-cast p2, Llyiahf/vczjk/yo1;

    invoke-virtual {p0, p1, p2}, Llyiahf/vczjk/ya8;->create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/ya8;

    sget-object p2, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    invoke-virtual {p1, p2}, Llyiahf/vczjk/ya8;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    return-object p1
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 11

    sget-object v0, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    iget v1, p0, Llyiahf/vczjk/ya8;->label:I

    const/4 v2, 0x1

    if-eqz v1, :cond_1

    if-ne v1, v2, :cond_0

    iget-wide v0, p0, Llyiahf/vczjk/ya8;->J$0:J

    iget-object v3, p0, Llyiahf/vczjk/ya8;->L$2:Ljava/lang/Object;

    check-cast v3, Llyiahf/vczjk/gl7;

    iget-object v4, p0, Llyiahf/vczjk/ya8;->L$1:Ljava/lang/Object;

    check-cast v4, Llyiahf/vczjk/db8;

    iget-object v5, p0, Llyiahf/vczjk/ya8;->L$0:Ljava/lang/Object;

    check-cast v5, Llyiahf/vczjk/db8;

    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    goto :goto_1

    :cond_0
    new-instance p1, Ljava/lang/IllegalStateException;

    const-string v0, "call to \'resume\' before \'invoke\' with coroutine"

    invoke-direct {p1, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p1

    :cond_1
    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    iget-object p1, p0, Llyiahf/vczjk/ya8;->L$0:Ljava/lang/Object;

    check-cast p1, Llyiahf/vczjk/lz5;

    new-instance v1, Llyiahf/vczjk/xa8;

    iget-object v4, p0, Llyiahf/vczjk/ya8;->this$0:Llyiahf/vczjk/db8;

    invoke-direct {v1, p1, v4}, Llyiahf/vczjk/xa8;-><init>(Llyiahf/vczjk/lz5;Llyiahf/vczjk/db8;)V

    iget-object v3, p0, Llyiahf/vczjk/ya8;->$result:Llyiahf/vczjk/gl7;

    iget-wide v5, p0, Llyiahf/vczjk/ya8;->$available:J

    iget-object p1, v4, Llyiahf/vczjk/db8;->OooO0OO:Llyiahf/vczjk/o23;

    iget-wide v7, v3, Llyiahf/vczjk/gl7;->element:J

    iget-object v9, v4, Llyiahf/vczjk/db8;->OooO0Oo:Llyiahf/vczjk/nf6;

    sget-object v10, Llyiahf/vczjk/nf6;->OooOOO:Llyiahf/vczjk/nf6;

    if-ne v9, v10, :cond_2

    invoke-static {v5, v6}, Llyiahf/vczjk/fea;->OooO0O0(J)F

    move-result v5

    goto :goto_0

    :cond_2
    invoke-static {v5, v6}, Llyiahf/vczjk/fea;->OooO0OO(J)F

    move-result v5

    :goto_0
    invoke-virtual {v4, v5}, Llyiahf/vczjk/db8;->OooO0OO(F)F

    move-result v5

    iput-object v4, p0, Llyiahf/vczjk/ya8;->L$0:Ljava/lang/Object;

    iput-object v4, p0, Llyiahf/vczjk/ya8;->L$1:Ljava/lang/Object;

    iput-object v3, p0, Llyiahf/vczjk/ya8;->L$2:Ljava/lang/Object;

    iput-wide v7, p0, Llyiahf/vczjk/ya8;->J$0:J

    iput v2, p0, Llyiahf/vczjk/ya8;->label:I

    invoke-interface {p1, v1, v5, p0}, Llyiahf/vczjk/o23;->OooO00o(Llyiahf/vczjk/xa8;FLlyiahf/vczjk/yo1;)Ljava/lang/Object;

    move-result-object p1

    if-ne p1, v0, :cond_3

    return-object v0

    :cond_3
    move-object v5, v4

    move-wide v0, v7

    :goto_1
    check-cast p1, Ljava/lang/Number;

    invoke-virtual {p1}, Ljava/lang/Number;->floatValue()F

    move-result p1

    invoke-virtual {v5, p1}, Llyiahf/vczjk/db8;->OooO0OO(F)F

    move-result p1

    iget-object v4, v4, Llyiahf/vczjk/db8;->OooO0Oo:Llyiahf/vczjk/nf6;

    sget-object v5, Llyiahf/vczjk/nf6;->OooOOO:Llyiahf/vczjk/nf6;

    const/4 v6, 0x0

    if-ne v4, v5, :cond_4

    const/4 v2, 0x2

    invoke-static {v0, v1, p1, v6, v2}, Llyiahf/vczjk/fea;->OooO00o(JFFI)J

    move-result-wide v0

    goto :goto_2

    :cond_4
    invoke-static {v0, v1, v6, p1, v2}, Llyiahf/vczjk/fea;->OooO00o(JFFI)J

    move-result-wide v0

    :goto_2
    iput-wide v0, v3, Llyiahf/vczjk/gl7;->element:J

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method
