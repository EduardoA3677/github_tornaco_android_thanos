.class public final Llyiahf/vczjk/tc8;
.super Llyiahf/vczjk/eb9;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/oe3;


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

    iput-object p1, p0, Llyiahf/vczjk/tc8;->$targetState:Ljava/lang/Object;

    iput-object p2, p0, Llyiahf/vczjk/tc8;->$oldTargetState:Ljava/lang/Object;

    iput-object p3, p0, Llyiahf/vczjk/tc8;->this$0:Llyiahf/vczjk/xc8;

    iput-object p4, p0, Llyiahf/vczjk/tc8;->$transition:Llyiahf/vczjk/bz9;

    iput p5, p0, Llyiahf/vczjk/tc8;->$fraction:F

    const/4 p1, 0x1

    invoke-direct {p0, p1, p6}, Llyiahf/vczjk/eb9;-><init>(ILlyiahf/vczjk/yo1;)V

    return-void
.end method


# virtual methods
.method public final OooO0o(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    check-cast p1, Llyiahf/vczjk/yo1;

    invoke-virtual {p0, p1}, Llyiahf/vczjk/tc8;->create(Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/tc8;

    sget-object v0, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    invoke-virtual {p1, v0}, Llyiahf/vczjk/tc8;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    return-object p1
.end method

.method public final create(Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;
    .locals 7

    new-instance v0, Llyiahf/vczjk/tc8;

    iget-object v1, p0, Llyiahf/vczjk/tc8;->$targetState:Ljava/lang/Object;

    iget-object v2, p0, Llyiahf/vczjk/tc8;->$oldTargetState:Ljava/lang/Object;

    iget-object v3, p0, Llyiahf/vczjk/tc8;->this$0:Llyiahf/vczjk/xc8;

    iget-object v4, p0, Llyiahf/vczjk/tc8;->$transition:Llyiahf/vczjk/bz9;

    iget v5, p0, Llyiahf/vczjk/tc8;->$fraction:F

    move-object v6, p1

    invoke-direct/range {v0 .. v6}, Llyiahf/vczjk/tc8;-><init>(Ljava/lang/Object;Ljava/lang/Object;Llyiahf/vczjk/xc8;Llyiahf/vczjk/bz9;FLlyiahf/vczjk/yo1;)V

    return-object v0
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 10

    sget-object v0, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    iget v1, p0, Llyiahf/vczjk/tc8;->label:I

    const/4 v2, 0x1

    if-eqz v1, :cond_1

    if-ne v1, v2, :cond_0

    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    goto :goto_0

    :cond_0
    new-instance p1, Ljava/lang/IllegalStateException;

    const-string v0, "call to \'resume\' before \'invoke\' with coroutine"

    invoke-direct {p1, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p1

    :cond_1
    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    new-instance v3, Llyiahf/vczjk/sc8;

    iget-object v4, p0, Llyiahf/vczjk/tc8;->$targetState:Ljava/lang/Object;

    iget-object v5, p0, Llyiahf/vczjk/tc8;->$oldTargetState:Ljava/lang/Object;

    iget-object v6, p0, Llyiahf/vczjk/tc8;->this$0:Llyiahf/vczjk/xc8;

    iget-object v7, p0, Llyiahf/vczjk/tc8;->$transition:Llyiahf/vczjk/bz9;

    iget v8, p0, Llyiahf/vczjk/tc8;->$fraction:F

    const/4 v9, 0x0

    invoke-direct/range {v3 .. v9}, Llyiahf/vczjk/sc8;-><init>(Ljava/lang/Object;Ljava/lang/Object;Llyiahf/vczjk/xc8;Llyiahf/vczjk/bz9;FLlyiahf/vczjk/yo1;)V

    iput v2, p0, Llyiahf/vczjk/tc8;->label:I

    invoke-static {v3, p0}, Llyiahf/vczjk/v34;->Oooo00O(Llyiahf/vczjk/ze3;Llyiahf/vczjk/yo1;)Ljava/lang/Object;

    move-result-object p1

    if-ne p1, v0, :cond_2

    return-object v0

    :cond_2
    :goto_0
    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method
