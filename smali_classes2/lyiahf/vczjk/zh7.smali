.class public final Llyiahf/vczjk/zh7;
.super Llyiahf/vczjk/eb9;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field synthetic L$0:Ljava/lang/Object;

.field label:I

.field final synthetic this$0:Llyiahf/vczjk/ai7;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/ai7;"
        }
    .end annotation
.end field


# direct methods
.method public constructor <init>(Llyiahf/vczjk/ai7;Llyiahf/vczjk/yo1;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/zh7;->this$0:Llyiahf/vczjk/ai7;

    const/4 p1, 0x2

    invoke-direct {p0, p1, p2}, Llyiahf/vczjk/eb9;-><init>(ILlyiahf/vczjk/yo1;)V

    return-void
.end method


# virtual methods
.method public final create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;
    .locals 2

    new-instance v0, Llyiahf/vczjk/zh7;

    iget-object v1, p0, Llyiahf/vczjk/zh7;->this$0:Llyiahf/vczjk/ai7;

    invoke-direct {v0, v1, p2}, Llyiahf/vczjk/zh7;-><init>(Llyiahf/vczjk/ai7;Llyiahf/vczjk/yo1;)V

    iput-object p1, v0, Llyiahf/vczjk/zh7;->L$0:Ljava/lang/Object;

    return-object v0
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    check-cast p1, Llyiahf/vczjk/oe3;

    check-cast p2, Llyiahf/vczjk/yo1;

    invoke-virtual {p0, p1, p2}, Llyiahf/vczjk/zh7;->create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/zh7;

    sget-object p2, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    invoke-virtual {p1, p2}, Llyiahf/vczjk/zh7;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    return-object p2
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 3

    sget-object v0, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    iget v0, p0, Llyiahf/vczjk/zh7;->label:I

    if-nez v0, :cond_1

    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    iget-object p1, p0, Llyiahf/vczjk/zh7;->L$0:Ljava/lang/Object;

    check-cast p1, Llyiahf/vczjk/oe3;

    iget-object v0, p0, Llyiahf/vczjk/zh7;->this$0:Llyiahf/vczjk/ai7;

    iget-object v0, v0, Llyiahf/vczjk/ai7;->OooO0o:Llyiahf/vczjk/s29;

    :cond_0
    invoke-virtual {v0}, Llyiahf/vczjk/s29;->getValue()Ljava/lang/Object;

    move-result-object v1

    invoke-interface {p1, v1}, Llyiahf/vczjk/oe3;->OooO0o(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v2

    invoke-virtual {v0, v1, v2}, Llyiahf/vczjk/s29;->OooOOO(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v1

    if-eqz v1, :cond_0

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1

    :cond_1
    new-instance p1, Ljava/lang/IllegalStateException;

    const-string v0, "call to \'resume\' before \'invoke\' with coroutine"

    invoke-direct {p1, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p1
.end method
