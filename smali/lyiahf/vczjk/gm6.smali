.class public final Llyiahf/vczjk/gm6;
.super Llyiahf/vczjk/eb9;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field final synthetic $page:I

.field final synthetic $pageOffsetFraction:F

.field label:I

.field final synthetic this$0:Llyiahf/vczjk/lm6;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/lm6;FILlyiahf/vczjk/yo1;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/gm6;->this$0:Llyiahf/vczjk/lm6;

    iput p2, p0, Llyiahf/vczjk/gm6;->$pageOffsetFraction:F

    iput p3, p0, Llyiahf/vczjk/gm6;->$page:I

    const/4 p1, 0x2

    invoke-direct {p0, p1, p4}, Llyiahf/vczjk/eb9;-><init>(ILlyiahf/vczjk/yo1;)V

    return-void
.end method


# virtual methods
.method public final create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;
    .locals 3

    new-instance p1, Llyiahf/vczjk/gm6;

    iget-object v0, p0, Llyiahf/vczjk/gm6;->this$0:Llyiahf/vczjk/lm6;

    iget v1, p0, Llyiahf/vczjk/gm6;->$pageOffsetFraction:F

    iget v2, p0, Llyiahf/vczjk/gm6;->$page:I

    invoke-direct {p1, v0, v1, v2, p2}, Llyiahf/vczjk/gm6;-><init>(Llyiahf/vczjk/lm6;FILlyiahf/vczjk/yo1;)V

    return-object p1
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    check-cast p1, Llyiahf/vczjk/v98;

    check-cast p2, Llyiahf/vczjk/yo1;

    invoke-virtual {p0, p1, p2}, Llyiahf/vczjk/gm6;->create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/gm6;

    sget-object p2, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    invoke-virtual {p1, p2}, Llyiahf/vczjk/gm6;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    return-object p1
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 6

    sget-object v0, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    iget v1, p0, Llyiahf/vczjk/gm6;->label:I

    sget-object v2, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    const/4 v3, 0x1

    if-eqz v1, :cond_1

    if-ne v1, v3, :cond_0

    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    goto :goto_1

    :cond_0
    new-instance p1, Ljava/lang/IllegalStateException;

    const-string v0, "call to \'resume\' before \'invoke\' with coroutine"

    invoke-direct {p1, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p1

    :cond_1
    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    iget-object p1, p0, Llyiahf/vczjk/gm6;->this$0:Llyiahf/vczjk/lm6;

    iput v3, p0, Llyiahf/vczjk/gm6;->label:I

    iget-object p1, p1, Llyiahf/vczjk/lm6;->OooOo0o:Llyiahf/vczjk/g20;

    invoke-virtual {p1, p0}, Llyiahf/vczjk/g20;->OooOO0(Llyiahf/vczjk/zo1;)Ljava/lang/Object;

    move-result-object p1

    if-ne p1, v0, :cond_2

    goto :goto_0

    :cond_2
    move-object p1, v2

    :goto_0
    if-ne p1, v0, :cond_3

    return-object v0

    :cond_3
    :goto_1
    iget p1, p0, Llyiahf/vczjk/gm6;->$pageOffsetFraction:F

    float-to-double v0, p1

    const-wide/high16 v4, -0x4020000000000000L    # -0.5

    cmpg-double v4, v4, v0

    if-gtz v4, :cond_4

    const-wide/high16 v4, 0x3fe0000000000000L    # 0.5

    cmpg-double v0, v0, v4

    if-gtz v0, :cond_4

    goto :goto_2

    :cond_4
    new-instance v0, Ljava/lang/StringBuilder;

    const-string v1, "pageOffsetFraction "

    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {v0, p1}, Ljava/lang/StringBuilder;->append(F)Ljava/lang/StringBuilder;

    const-string p1, " is not within the range -0.5 to 0.5"

    invoke-virtual {v0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object p1

    invoke-static {p1}, Llyiahf/vczjk/sz3;->OooO00o(Ljava/lang/String;)V

    :goto_2
    iget-object p1, p0, Llyiahf/vczjk/gm6;->this$0:Llyiahf/vczjk/lm6;

    iget v0, p0, Llyiahf/vczjk/gm6;->$page:I

    invoke-virtual {p1, v0}, Llyiahf/vczjk/lm6;->OooO(I)I

    move-result p1

    iget-object v0, p0, Llyiahf/vczjk/gm6;->this$0:Llyiahf/vczjk/lm6;

    iget v1, p0, Llyiahf/vczjk/gm6;->$pageOffsetFraction:F

    invoke-virtual {v0, v1, p1, v3}, Llyiahf/vczjk/lm6;->OooOOoo(FIZ)V

    return-object v2
.end method
