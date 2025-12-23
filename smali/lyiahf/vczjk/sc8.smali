.class public final Llyiahf/vczjk/sc8;
.super Llyiahf/vczjk/eb9;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field final synthetic $fraction:F

.field final synthetic $oldTargetState:Ljava/lang/Object;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/lang/Object;"
        }
    .end annotation
.end field

.field final synthetic $targetState:Ljava/lang/Object;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/lang/Object;"
        }
    .end annotation
.end field

.field final synthetic $transition:Llyiahf/vczjk/bz9;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/bz9;"
        }
    .end annotation
.end field

.field private synthetic L$0:Ljava/lang/Object;

.field label:I

.field final synthetic this$0:Llyiahf/vczjk/xc8;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/xc8;"
        }
    .end annotation
.end field


# direct methods
.method public constructor <init>(Ljava/lang/Object;Ljava/lang/Object;Llyiahf/vczjk/xc8;Llyiahf/vczjk/bz9;FLlyiahf/vczjk/yo1;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/sc8;->$targetState:Ljava/lang/Object;

    iput-object p2, p0, Llyiahf/vczjk/sc8;->$oldTargetState:Ljava/lang/Object;

    iput-object p3, p0, Llyiahf/vczjk/sc8;->this$0:Llyiahf/vczjk/xc8;

    iput-object p4, p0, Llyiahf/vczjk/sc8;->$transition:Llyiahf/vczjk/bz9;

    iput p5, p0, Llyiahf/vczjk/sc8;->$fraction:F

    const/4 p1, 0x2

    invoke-direct {p0, p1, p6}, Llyiahf/vczjk/eb9;-><init>(ILlyiahf/vczjk/yo1;)V

    return-void
.end method


# virtual methods
.method public final create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;
    .locals 7

    new-instance v0, Llyiahf/vczjk/sc8;

    iget-object v1, p0, Llyiahf/vczjk/sc8;->$targetState:Ljava/lang/Object;

    iget-object v2, p0, Llyiahf/vczjk/sc8;->$oldTargetState:Ljava/lang/Object;

    iget-object v3, p0, Llyiahf/vczjk/sc8;->this$0:Llyiahf/vczjk/xc8;

    iget-object v4, p0, Llyiahf/vczjk/sc8;->$transition:Llyiahf/vczjk/bz9;

    iget v5, p0, Llyiahf/vczjk/sc8;->$fraction:F

    move-object v6, p2

    invoke-direct/range {v0 .. v6}, Llyiahf/vczjk/sc8;-><init>(Ljava/lang/Object;Ljava/lang/Object;Llyiahf/vczjk/xc8;Llyiahf/vczjk/bz9;FLlyiahf/vczjk/yo1;)V

    iput-object p1, v0, Llyiahf/vczjk/sc8;->L$0:Ljava/lang/Object;

    return-object v0
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    check-cast p1, Llyiahf/vczjk/xr1;

    check-cast p2, Llyiahf/vczjk/yo1;

    invoke-virtual {p0, p1, p2}, Llyiahf/vczjk/sc8;->create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/sc8;

    sget-object p2, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    invoke-virtual {p1, p2}, Llyiahf/vczjk/sc8;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    return-object p1
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 7

    sget-object v0, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    iget v1, p0, Llyiahf/vczjk/sc8;->label:I

    sget-object v2, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    const/4 v3, 0x1

    if-eqz v1, :cond_1

    if-ne v1, v3, :cond_0

    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    goto/16 :goto_2

    :cond_0
    new-instance p1, Ljava/lang/IllegalStateException;

    const-string v0, "call to \'resume\' before \'invoke\' with coroutine"

    invoke-direct {p1, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p1

    :cond_1
    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    iget-object p1, p0, Llyiahf/vczjk/sc8;->L$0:Ljava/lang/Object;

    check-cast p1, Llyiahf/vczjk/xr1;

    iget-object v1, p0, Llyiahf/vczjk/sc8;->$targetState:Ljava/lang/Object;

    iget-object v4, p0, Llyiahf/vczjk/sc8;->$oldTargetState:Ljava/lang/Object;

    invoke-static {v1, v4}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v1

    const/4 v4, 0x0

    if-nez v1, :cond_2

    iget-object v1, p0, Llyiahf/vczjk/sc8;->this$0:Llyiahf/vczjk/xc8;

    invoke-static {v1}, Llyiahf/vczjk/xc8;->OooO0o(Llyiahf/vczjk/xc8;)V

    goto :goto_0

    :cond_2
    iget-object v1, p0, Llyiahf/vczjk/sc8;->this$0:Llyiahf/vczjk/xc8;

    iput-object v4, v1, Llyiahf/vczjk/xc8;->OooOOO:Llyiahf/vczjk/kc8;

    iget-object v1, v1, Llyiahf/vczjk/xc8;->OooO0OO:Llyiahf/vczjk/qs5;

    check-cast v1, Llyiahf/vczjk/fw8;

    invoke-virtual {v1}, Llyiahf/vczjk/fw8;->getValue()Ljava/lang/Object;

    move-result-object v1

    iget-object v5, p0, Llyiahf/vczjk/sc8;->$targetState:Ljava/lang/Object;

    invoke-static {v1, v5}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v1

    if-eqz v1, :cond_3

    return-object v2

    :cond_3
    :goto_0
    iget-object v1, p0, Llyiahf/vczjk/sc8;->$targetState:Ljava/lang/Object;

    iget-object v5, p0, Llyiahf/vczjk/sc8;->$oldTargetState:Ljava/lang/Object;

    invoke-static {v1, v5}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v1

    if-nez v1, :cond_4

    iget-object v1, p0, Llyiahf/vczjk/sc8;->$transition:Llyiahf/vczjk/bz9;

    iget-object v5, p0, Llyiahf/vczjk/sc8;->$targetState:Ljava/lang/Object;

    invoke-virtual {v1, v5}, Llyiahf/vczjk/bz9;->OooOOo(Ljava/lang/Object;)V

    iget-object v1, p0, Llyiahf/vczjk/sc8;->$transition:Llyiahf/vczjk/bz9;

    const-wide/16 v5, 0x0

    invoke-virtual {v1, v5, v6}, Llyiahf/vczjk/bz9;->OooOOOo(J)V

    iget-object v1, p0, Llyiahf/vczjk/sc8;->this$0:Llyiahf/vczjk/xc8;

    iget-object v5, p0, Llyiahf/vczjk/sc8;->$targetState:Ljava/lang/Object;

    iget-object v1, v1, Llyiahf/vczjk/xc8;->OooO0O0:Llyiahf/vczjk/qs5;

    check-cast v1, Llyiahf/vczjk/fw8;

    invoke-virtual {v1, v5}, Llyiahf/vczjk/fw8;->setValue(Ljava/lang/Object;)V

    iget-object v1, p0, Llyiahf/vczjk/sc8;->$transition:Llyiahf/vczjk/bz9;

    iget v5, p0, Llyiahf/vczjk/sc8;->$fraction:F

    invoke-virtual {v1, v5}, Llyiahf/vczjk/bz9;->OooOO0o(F)V

    :cond_4
    iget-object v1, p0, Llyiahf/vczjk/sc8;->this$0:Llyiahf/vczjk/xc8;

    iget v5, p0, Llyiahf/vczjk/sc8;->$fraction:F

    invoke-virtual {v1, v5}, Llyiahf/vczjk/xc8;->OooOOOo(F)V

    iget-object v1, p0, Llyiahf/vczjk/sc8;->this$0:Llyiahf/vczjk/xc8;

    iget-object v1, v1, Llyiahf/vczjk/xc8;->OooOOO0:Llyiahf/vczjk/as5;

    invoke-virtual {v1}, Llyiahf/vczjk/c76;->OooO0o0()Z

    move-result v1

    if-eqz v1, :cond_5

    new-instance v1, Llyiahf/vczjk/rc8;

    iget-object v5, p0, Llyiahf/vczjk/sc8;->this$0:Llyiahf/vczjk/xc8;

    invoke-direct {v1, v5, v4}, Llyiahf/vczjk/rc8;-><init>(Llyiahf/vczjk/xc8;Llyiahf/vczjk/yo1;)V

    const/4 v5, 0x3

    invoke-static {p1, v4, v4, v1, v5}, Llyiahf/vczjk/os9;->Oooo0O0(Llyiahf/vczjk/xr1;Llyiahf/vczjk/or1;Llyiahf/vczjk/as1;Llyiahf/vczjk/ze3;I)Llyiahf/vczjk/r09;

    goto :goto_1

    :cond_5
    iget-object p1, p0, Llyiahf/vczjk/sc8;->this$0:Llyiahf/vczjk/xc8;

    const-wide/high16 v4, -0x8000000000000000L

    iput-wide v4, p1, Llyiahf/vczjk/xc8;->OooOO0o:J

    :goto_1
    iget-object p1, p0, Llyiahf/vczjk/sc8;->this$0:Llyiahf/vczjk/xc8;

    iput v3, p0, Llyiahf/vczjk/sc8;->label:I

    invoke-static {p1, p0}, Llyiahf/vczjk/xc8;->OooOO0(Llyiahf/vczjk/xc8;Llyiahf/vczjk/zo1;)Ljava/lang/Object;

    move-result-object p1

    if-ne p1, v0, :cond_6

    return-object v0

    :cond_6
    :goto_2
    iget-object p1, p0, Llyiahf/vczjk/sc8;->this$0:Llyiahf/vczjk/xc8;

    invoke-virtual {p1}, Llyiahf/vczjk/xc8;->OooOOOO()V

    return-object v2
.end method
