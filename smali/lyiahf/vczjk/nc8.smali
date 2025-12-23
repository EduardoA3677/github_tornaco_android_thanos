.class public final Llyiahf/vczjk/nc8;
.super Llyiahf/vczjk/eb9;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/oe3;


# instance fields
.field final synthetic $animationSpec:Llyiahf/vczjk/p13;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/p13;"
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
.method public constructor <init>(Ljava/lang/Object;Llyiahf/vczjk/yo1;Llyiahf/vczjk/p13;Llyiahf/vczjk/xc8;Llyiahf/vczjk/bz9;)V
    .locals 0

    iput-object p5, p0, Llyiahf/vczjk/nc8;->$transition:Llyiahf/vczjk/bz9;

    iput-object p4, p0, Llyiahf/vczjk/nc8;->this$0:Llyiahf/vczjk/xc8;

    iput-object p1, p0, Llyiahf/vczjk/nc8;->$targetState:Ljava/lang/Object;

    iput-object p3, p0, Llyiahf/vczjk/nc8;->$animationSpec:Llyiahf/vczjk/p13;

    const/4 p1, 0x1

    invoke-direct {p0, p1, p2}, Llyiahf/vczjk/eb9;-><init>(ILlyiahf/vczjk/yo1;)V

    return-void
.end method


# virtual methods
.method public final OooO0o(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    check-cast p1, Llyiahf/vczjk/yo1;

    invoke-virtual {p0, p1}, Llyiahf/vczjk/nc8;->create(Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/nc8;

    sget-object v0, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    invoke-virtual {p1, v0}, Llyiahf/vczjk/nc8;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    return-object p1
.end method

.method public final create(Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;
    .locals 6

    new-instance v0, Llyiahf/vczjk/nc8;

    iget-object v5, p0, Llyiahf/vczjk/nc8;->$transition:Llyiahf/vczjk/bz9;

    iget-object v4, p0, Llyiahf/vczjk/nc8;->this$0:Llyiahf/vczjk/xc8;

    iget-object v1, p0, Llyiahf/vczjk/nc8;->$targetState:Ljava/lang/Object;

    iget-object v3, p0, Llyiahf/vczjk/nc8;->$animationSpec:Llyiahf/vczjk/p13;

    move-object v2, p1

    invoke-direct/range {v0 .. v5}, Llyiahf/vczjk/nc8;-><init>(Ljava/lang/Object;Llyiahf/vczjk/yo1;Llyiahf/vczjk/p13;Llyiahf/vczjk/xc8;Llyiahf/vczjk/bz9;)V

    return-object v0
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 9

    sget-object v0, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    iget v1, p0, Llyiahf/vczjk/nc8;->label:I

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

    new-instance v3, Llyiahf/vczjk/mc8;

    iget-object v7, p0, Llyiahf/vczjk/nc8;->this$0:Llyiahf/vczjk/xc8;

    iget-object v4, p0, Llyiahf/vczjk/nc8;->$targetState:Ljava/lang/Object;

    iget-object v8, p0, Llyiahf/vczjk/nc8;->$transition:Llyiahf/vczjk/bz9;

    iget-object v6, p0, Llyiahf/vczjk/nc8;->$animationSpec:Llyiahf/vczjk/p13;

    const/4 v5, 0x0

    invoke-direct/range {v3 .. v8}, Llyiahf/vczjk/mc8;-><init>(Ljava/lang/Object;Llyiahf/vczjk/yo1;Llyiahf/vczjk/p13;Llyiahf/vczjk/xc8;Llyiahf/vczjk/bz9;)V

    iput v2, p0, Llyiahf/vczjk/nc8;->label:I

    invoke-static {v3, p0}, Llyiahf/vczjk/v34;->Oooo00O(Llyiahf/vczjk/ze3;Llyiahf/vczjk/yo1;)Ljava/lang/Object;

    move-result-object p1

    if-ne p1, v0, :cond_2

    return-object v0

    :cond_2
    :goto_0
    iget-object p1, p0, Llyiahf/vczjk/nc8;->$transition:Llyiahf/vczjk/bz9;

    invoke-virtual {p1}, Llyiahf/vczjk/bz9;->OooOO0O()V

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method
