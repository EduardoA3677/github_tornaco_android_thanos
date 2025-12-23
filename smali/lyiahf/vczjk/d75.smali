.class public final Llyiahf/vczjk/d75;
.super Llyiahf/vczjk/eb9;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/oe3;


# instance fields
.field final synthetic $cancellationBehavior:Llyiahf/vczjk/x75;

.field final synthetic $clipSpec:Llyiahf/vczjk/y75;

.field final synthetic $composition:Llyiahf/vczjk/z75;

.field final synthetic $continueFromPreviousAnimate:Z

.field final synthetic $initialProgress:F

.field final synthetic $iteration:I

.field final synthetic $iterations:I

.field final synthetic $reverseOnRepeat:Z

.field final synthetic $speed:F

.field final synthetic $useCompositionFrameRate:Z

.field label:I

.field final synthetic this$0:Llyiahf/vczjk/k75;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/k75;IIZFLlyiahf/vczjk/z75;FZZLlyiahf/vczjk/x75;Llyiahf/vczjk/yo1;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/d75;->this$0:Llyiahf/vczjk/k75;

    iput p2, p0, Llyiahf/vczjk/d75;->$iteration:I

    iput p3, p0, Llyiahf/vczjk/d75;->$iterations:I

    iput-boolean p4, p0, Llyiahf/vczjk/d75;->$reverseOnRepeat:Z

    iput p5, p0, Llyiahf/vczjk/d75;->$speed:F

    iput-object p6, p0, Llyiahf/vczjk/d75;->$composition:Llyiahf/vczjk/z75;

    iput p7, p0, Llyiahf/vczjk/d75;->$initialProgress:F

    iput-boolean p8, p0, Llyiahf/vczjk/d75;->$useCompositionFrameRate:Z

    iput-boolean p9, p0, Llyiahf/vczjk/d75;->$continueFromPreviousAnimate:Z

    iput-object p10, p0, Llyiahf/vczjk/d75;->$cancellationBehavior:Llyiahf/vczjk/x75;

    const/4 p1, 0x1

    invoke-direct {p0, p1, p11}, Llyiahf/vczjk/eb9;-><init>(ILlyiahf/vczjk/yo1;)V

    return-void
.end method


# virtual methods
.method public final OooO0o(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    check-cast p1, Llyiahf/vczjk/yo1;

    invoke-virtual {p0, p1}, Llyiahf/vczjk/d75;->create(Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/d75;

    sget-object v0, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    invoke-virtual {p1, v0}, Llyiahf/vczjk/d75;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    return-object p1
.end method

.method public final create(Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;
    .locals 12

    new-instance v0, Llyiahf/vczjk/d75;

    iget-object v1, p0, Llyiahf/vczjk/d75;->this$0:Llyiahf/vczjk/k75;

    iget v2, p0, Llyiahf/vczjk/d75;->$iteration:I

    iget v3, p0, Llyiahf/vczjk/d75;->$iterations:I

    iget-boolean v4, p0, Llyiahf/vczjk/d75;->$reverseOnRepeat:Z

    iget v5, p0, Llyiahf/vczjk/d75;->$speed:F

    iget-object v6, p0, Llyiahf/vczjk/d75;->$composition:Llyiahf/vczjk/z75;

    iget v7, p0, Llyiahf/vczjk/d75;->$initialProgress:F

    iget-boolean v8, p0, Llyiahf/vczjk/d75;->$useCompositionFrameRate:Z

    iget-boolean v9, p0, Llyiahf/vczjk/d75;->$continueFromPreviousAnimate:Z

    iget-object v10, p0, Llyiahf/vczjk/d75;->$cancellationBehavior:Llyiahf/vczjk/x75;

    move-object v11, p1

    invoke-direct/range {v0 .. v11}, Llyiahf/vczjk/d75;-><init>(Llyiahf/vczjk/k75;IIZFLlyiahf/vczjk/z75;FZZLlyiahf/vczjk/x75;Llyiahf/vczjk/yo1;)V

    return-object v0
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 12

    sget-object v0, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    iget v1, p0, Llyiahf/vczjk/d75;->label:I

    sget-object v2, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    const/4 v3, 0x0

    const/4 v4, 0x1

    if-eqz v1, :cond_1

    if-ne v1, v4, :cond_0

    :try_start_0
    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    goto/16 :goto_1

    :catchall_0
    move-exception v0

    move-object p1, v0

    goto/16 :goto_2

    :cond_0
    new-instance p1, Ljava/lang/IllegalStateException;

    const-string v0, "call to \'resume\' before \'invoke\' with coroutine"

    invoke-direct {p1, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p1

    :cond_1
    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    iget-object p1, p0, Llyiahf/vczjk/d75;->this$0:Llyiahf/vczjk/k75;

    iget v1, p0, Llyiahf/vczjk/d75;->$iteration:I

    invoke-virtual {p1, v1}, Llyiahf/vczjk/k75;->OooO0oO(I)V

    iget-object p1, p0, Llyiahf/vczjk/d75;->this$0:Llyiahf/vczjk/k75;

    iget v1, p0, Llyiahf/vczjk/d75;->$iterations:I

    iget-object p1, p1, Llyiahf/vczjk/k75;->OooOOOO:Llyiahf/vczjk/qs5;

    invoke-static {v1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v1

    check-cast p1, Llyiahf/vczjk/fw8;

    invoke-virtual {p1, v1}, Llyiahf/vczjk/fw8;->setValue(Ljava/lang/Object;)V

    iget-object p1, p0, Llyiahf/vczjk/d75;->this$0:Llyiahf/vczjk/k75;

    iget-boolean v1, p0, Llyiahf/vczjk/d75;->$reverseOnRepeat:Z

    iget-object p1, p1, Llyiahf/vczjk/k75;->OooOOOo:Llyiahf/vczjk/qs5;

    invoke-static {v1}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    move-result-object v1

    check-cast p1, Llyiahf/vczjk/fw8;

    invoke-virtual {p1, v1}, Llyiahf/vczjk/fw8;->setValue(Ljava/lang/Object;)V

    iget-object p1, p0, Llyiahf/vczjk/d75;->this$0:Llyiahf/vczjk/k75;

    iget v1, p0, Llyiahf/vczjk/d75;->$speed:F

    iget-object p1, p1, Llyiahf/vczjk/k75;->OooOOo:Llyiahf/vczjk/qs5;

    invoke-static {v1}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    move-result-object v1

    check-cast p1, Llyiahf/vczjk/fw8;

    invoke-virtual {p1, v1}, Llyiahf/vczjk/fw8;->setValue(Ljava/lang/Object;)V

    iget-object p1, p0, Llyiahf/vczjk/d75;->this$0:Llyiahf/vczjk/k75;

    iget-object p1, p1, Llyiahf/vczjk/k75;->OooOOo0:Llyiahf/vczjk/qs5;

    check-cast p1, Llyiahf/vczjk/fw8;

    const/4 v1, 0x0

    invoke-virtual {p1, v1}, Llyiahf/vczjk/fw8;->setValue(Ljava/lang/Object;)V

    iget-object p1, p0, Llyiahf/vczjk/d75;->this$0:Llyiahf/vczjk/k75;

    iget-object v1, p0, Llyiahf/vczjk/d75;->$composition:Llyiahf/vczjk/z75;

    iget-object p1, p1, Llyiahf/vczjk/k75;->OooOo0:Llyiahf/vczjk/qs5;

    check-cast p1, Llyiahf/vczjk/fw8;

    invoke-virtual {p1, v1}, Llyiahf/vczjk/fw8;->setValue(Ljava/lang/Object;)V

    iget-object p1, p0, Llyiahf/vczjk/d75;->this$0:Llyiahf/vczjk/k75;

    iget v1, p0, Llyiahf/vczjk/d75;->$initialProgress:F

    invoke-virtual {p1, v1}, Llyiahf/vczjk/k75;->OooO0oo(F)V

    iget-object p1, p0, Llyiahf/vczjk/d75;->this$0:Llyiahf/vczjk/k75;

    iget-boolean v1, p0, Llyiahf/vczjk/d75;->$useCompositionFrameRate:Z

    iget-object p1, p1, Llyiahf/vczjk/k75;->OooOOoo:Llyiahf/vczjk/qs5;

    invoke-static {v1}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    move-result-object v1

    check-cast p1, Llyiahf/vczjk/fw8;

    invoke-virtual {p1, v1}, Llyiahf/vczjk/fw8;->setValue(Ljava/lang/Object;)V

    iget-boolean p1, p0, Llyiahf/vczjk/d75;->$continueFromPreviousAnimate:Z

    if-nez p1, :cond_2

    iget-object p1, p0, Llyiahf/vczjk/d75;->this$0:Llyiahf/vczjk/k75;

    iget-object p1, p1, Llyiahf/vczjk/k75;->OooOo:Llyiahf/vczjk/qs5;

    const-wide/high16 v5, -0x8000000000000000L

    invoke-static {v5, v6}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    move-result-object v1

    check-cast p1, Llyiahf/vczjk/fw8;

    invoke-virtual {p1, v1}, Llyiahf/vczjk/fw8;->setValue(Ljava/lang/Object;)V

    :cond_2
    iget-object p1, p0, Llyiahf/vczjk/d75;->$composition:Llyiahf/vczjk/z75;

    if-nez p1, :cond_3

    iget-object p1, p0, Llyiahf/vczjk/d75;->this$0:Llyiahf/vczjk/k75;

    invoke-static {p1, v3}, Llyiahf/vczjk/k75;->OooO0O0(Llyiahf/vczjk/k75;Z)V

    return-object v2

    :cond_3
    iget p1, p0, Llyiahf/vczjk/d75;->$speed:F

    invoke-static {p1}, Ljava/lang/Float;->isInfinite(F)Z

    move-result p1

    if-eqz p1, :cond_4

    iget-object p1, p0, Llyiahf/vczjk/d75;->this$0:Llyiahf/vczjk/k75;

    invoke-virtual {p1}, Llyiahf/vczjk/k75;->OooO0OO()F

    move-result v0

    invoke-virtual {p1, v0}, Llyiahf/vczjk/k75;->OooO0oo(F)V

    iget-object p1, p0, Llyiahf/vczjk/d75;->this$0:Llyiahf/vczjk/k75;

    invoke-static {p1, v3}, Llyiahf/vczjk/k75;->OooO0O0(Llyiahf/vczjk/k75;Z)V

    iget-object p1, p0, Llyiahf/vczjk/d75;->this$0:Llyiahf/vczjk/k75;

    iget v0, p0, Llyiahf/vczjk/d75;->$iterations:I

    invoke-virtual {p1, v0}, Llyiahf/vczjk/k75;->OooO0oO(I)V

    return-object v2

    :cond_4
    iget-object p1, p0, Llyiahf/vczjk/d75;->this$0:Llyiahf/vczjk/k75;

    invoke-static {p1, v4}, Llyiahf/vczjk/k75;->OooO0O0(Llyiahf/vczjk/k75;Z)V

    :try_start_1
    iget-object p1, p0, Llyiahf/vczjk/d75;->$cancellationBehavior:Llyiahf/vczjk/x75;

    invoke-virtual {p1}, Ljava/lang/Enum;->ordinal()I

    move-result p1

    if-eqz p1, :cond_6

    if-ne p1, v4, :cond_5

    sget-object p1, Llyiahf/vczjk/h26;->OooOOO:Llyiahf/vczjk/h26;

    goto :goto_0

    :cond_5
    new-instance p1, Llyiahf/vczjk/k61;

    invoke-direct {p1}, Ljava/lang/RuntimeException;-><init>()V

    throw p1

    :cond_6
    sget-object p1, Llyiahf/vczjk/wm2;->OooOOO0:Llyiahf/vczjk/wm2;

    :goto_0
    invoke-interface {p0}, Llyiahf/vczjk/yo1;->getContext()Llyiahf/vczjk/or1;

    move-result-object v1

    invoke-static {v1}, Llyiahf/vczjk/zsa;->OoooOOo(Llyiahf/vczjk/or1;)Llyiahf/vczjk/v74;

    move-result-object v7

    new-instance v5, Llyiahf/vczjk/c75;

    iget-object v6, p0, Llyiahf/vczjk/d75;->$cancellationBehavior:Llyiahf/vczjk/x75;

    iget v8, p0, Llyiahf/vczjk/d75;->$iterations:I

    iget v9, p0, Llyiahf/vczjk/d75;->$iteration:I

    iget-object v10, p0, Llyiahf/vczjk/d75;->this$0:Llyiahf/vczjk/k75;

    const/4 v11, 0x0

    invoke-direct/range {v5 .. v11}, Llyiahf/vczjk/c75;-><init>(Llyiahf/vczjk/x75;Llyiahf/vczjk/v74;IILlyiahf/vczjk/k75;Llyiahf/vczjk/yo1;)V

    iput v4, p0, Llyiahf/vczjk/d75;->label:I

    invoke-static {p1, v5, p0}, Llyiahf/vczjk/os9;->OoooOoO(Llyiahf/vczjk/or1;Llyiahf/vczjk/ze3;Llyiahf/vczjk/yo1;)Ljava/lang/Object;

    move-result-object p1

    if-ne p1, v0, :cond_7

    return-object v0

    :cond_7
    :goto_1
    invoke-interface {p0}, Llyiahf/vczjk/yo1;->getContext()Llyiahf/vczjk/or1;

    move-result-object p1

    invoke-static {p1}, Llyiahf/vczjk/zsa;->Oooo0oo(Llyiahf/vczjk/or1;)V
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    iget-object p1, p0, Llyiahf/vczjk/d75;->this$0:Llyiahf/vczjk/k75;

    invoke-static {p1, v3}, Llyiahf/vczjk/k75;->OooO0O0(Llyiahf/vczjk/k75;Z)V

    return-object v2

    :goto_2
    iget-object v0, p0, Llyiahf/vczjk/d75;->this$0:Llyiahf/vczjk/k75;

    invoke-static {v0, v3}, Llyiahf/vczjk/k75;->OooO0O0(Llyiahf/vczjk/k75;Z)V

    throw p1
.end method
