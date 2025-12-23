.class public final Llyiahf/vczjk/e22;
.super Llyiahf/vczjk/eb9;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field final synthetic $initialVelocity:F

.field final synthetic $this_performFling:Llyiahf/vczjk/v98;

.field L$0:Ljava/lang/Object;

.field L$1:Ljava/lang/Object;

.field label:I

.field final synthetic this$0:Llyiahf/vczjk/f22;


# direct methods
.method public constructor <init>(FLlyiahf/vczjk/f22;Llyiahf/vczjk/v98;Llyiahf/vczjk/yo1;)V
    .locals 0

    iput p1, p0, Llyiahf/vczjk/e22;->$initialVelocity:F

    iput-object p2, p0, Llyiahf/vczjk/e22;->this$0:Llyiahf/vczjk/f22;

    iput-object p3, p0, Llyiahf/vczjk/e22;->$this_performFling:Llyiahf/vczjk/v98;

    const/4 p1, 0x2

    invoke-direct {p0, p1, p4}, Llyiahf/vczjk/eb9;-><init>(ILlyiahf/vczjk/yo1;)V

    return-void
.end method


# virtual methods
.method public final create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;
    .locals 3

    new-instance p1, Llyiahf/vczjk/e22;

    iget v0, p0, Llyiahf/vczjk/e22;->$initialVelocity:F

    iget-object v1, p0, Llyiahf/vczjk/e22;->this$0:Llyiahf/vczjk/f22;

    iget-object v2, p0, Llyiahf/vczjk/e22;->$this_performFling:Llyiahf/vczjk/v98;

    invoke-direct {p1, v0, v1, v2, p2}, Llyiahf/vczjk/e22;-><init>(FLlyiahf/vczjk/f22;Llyiahf/vczjk/v98;Llyiahf/vczjk/yo1;)V

    return-object p1
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    check-cast p1, Llyiahf/vczjk/xr1;

    check-cast p2, Llyiahf/vczjk/yo1;

    invoke-virtual {p0, p1, p2}, Llyiahf/vczjk/e22;->create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/e22;

    sget-object p2, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    invoke-virtual {p1, p2}, Llyiahf/vczjk/e22;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    return-object p1
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 8

    sget-object v0, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    iget v1, p0, Llyiahf/vczjk/e22;->label:I

    const/4 v2, 0x1

    if-eqz v1, :cond_1

    if-ne v1, v2, :cond_0

    iget-object v0, p0, Llyiahf/vczjk/e22;->L$1:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/xl;

    iget-object v1, p0, Llyiahf/vczjk/e22;->L$0:Ljava/lang/Object;

    check-cast v1, Llyiahf/vczjk/el7;

    :try_start_0
    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V
    :try_end_0
    .catch Ljava/util/concurrent/CancellationException; {:try_start_0 .. :try_end_0} :catch_1

    goto :goto_0

    :cond_0
    new-instance p1, Ljava/lang/IllegalStateException;

    const-string v0, "call to \'resume\' before \'invoke\' with coroutine"

    invoke-direct {p1, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p1

    :cond_1
    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    iget p1, p0, Llyiahf/vczjk/e22;->$initialVelocity:F

    invoke-static {p1}, Ljava/lang/Math;->abs(F)F

    move-result p1

    const/high16 v1, 0x3f800000    # 1.0f

    cmpl-float p1, p1, v1

    if-lez p1, :cond_3

    new-instance v1, Llyiahf/vczjk/el7;

    invoke-direct {v1}, Ljava/lang/Object;-><init>()V

    iget p1, p0, Llyiahf/vczjk/e22;->$initialVelocity:F

    iput p1, v1, Llyiahf/vczjk/el7;->element:F

    new-instance v3, Llyiahf/vczjk/el7;

    invoke-direct {v3}, Ljava/lang/Object;-><init>()V

    const/16 v4, 0x1c

    const/4 v5, 0x0

    invoke-static {v5, p1, v4}, Llyiahf/vczjk/tg0;->OooO0OO(FFI)Llyiahf/vczjk/xl;

    move-result-object p1

    :try_start_1
    iget-object v4, p0, Llyiahf/vczjk/e22;->this$0:Llyiahf/vczjk/f22;

    iget-object v5, v4, Llyiahf/vczjk/f22;->OooO00o:Llyiahf/vczjk/t02;

    new-instance v6, Llyiahf/vczjk/d22;

    iget-object v7, p0, Llyiahf/vczjk/e22;->$this_performFling:Llyiahf/vczjk/v98;

    invoke-direct {v6, v3, v7, v1, v4}, Llyiahf/vczjk/d22;-><init>(Llyiahf/vczjk/el7;Llyiahf/vczjk/v98;Llyiahf/vczjk/el7;Llyiahf/vczjk/f22;)V

    iput-object v1, p0, Llyiahf/vczjk/e22;->L$0:Ljava/lang/Object;

    iput-object p1, p0, Llyiahf/vczjk/e22;->L$1:Ljava/lang/Object;

    iput v2, p0, Llyiahf/vczjk/e22;->label:I

    const/4 v2, 0x0

    invoke-static {p1, v5, v2, v6, p0}, Llyiahf/vczjk/vc6;->OooOO0O(Llyiahf/vczjk/xl;Llyiahf/vczjk/t02;ZLlyiahf/vczjk/oe3;Llyiahf/vczjk/zo1;)Ljava/lang/Object;

    move-result-object p1
    :try_end_1
    .catch Ljava/util/concurrent/CancellationException; {:try_start_1 .. :try_end_1} :catch_0

    if-ne p1, v0, :cond_2

    return-object v0

    :catch_0
    move-object v0, p1

    :catch_1
    invoke-virtual {v0}, Llyiahf/vczjk/xl;->OooO00o()Ljava/lang/Object;

    move-result-object p1

    check-cast p1, Ljava/lang/Number;

    invoke-virtual {p1}, Ljava/lang/Number;->floatValue()F

    move-result p1

    iput p1, v1, Llyiahf/vczjk/el7;->element:F

    :cond_2
    :goto_0
    iget p1, v1, Llyiahf/vczjk/el7;->element:F

    goto :goto_1

    :cond_3
    iget p1, p0, Llyiahf/vczjk/e22;->$initialVelocity:F

    :goto_1
    new-instance v0, Ljava/lang/Float;

    invoke-direct {v0, p1}, Ljava/lang/Float;-><init>(F)V

    return-object v0
.end method
