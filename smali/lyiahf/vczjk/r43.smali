.class public final Llyiahf/vczjk/r43;
.super Llyiahf/vczjk/eb9;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field final synthetic $operation:Llyiahf/vczjk/bf3;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/bf3;"
        }
    .end annotation
.end field

.field final synthetic $this_simpleRunningReduce:Llyiahf/vczjk/f43;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/f43;"
        }
    .end annotation
.end field

.field private synthetic L$0:Ljava/lang/Object;

.field label:I


# direct methods
.method public constructor <init>(Llyiahf/vczjk/f43;Llyiahf/vczjk/bf3;Llyiahf/vczjk/yo1;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/r43;->$this_simpleRunningReduce:Llyiahf/vczjk/f43;

    iput-object p2, p0, Llyiahf/vczjk/r43;->$operation:Llyiahf/vczjk/bf3;

    const/4 p1, 0x2

    invoke-direct {p0, p1, p3}, Llyiahf/vczjk/eb9;-><init>(ILlyiahf/vczjk/yo1;)V

    return-void
.end method


# virtual methods
.method public final create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;
    .locals 3

    new-instance v0, Llyiahf/vczjk/r43;

    iget-object v1, p0, Llyiahf/vczjk/r43;->$this_simpleRunningReduce:Llyiahf/vczjk/f43;

    iget-object v2, p0, Llyiahf/vczjk/r43;->$operation:Llyiahf/vczjk/bf3;

    invoke-direct {v0, v1, v2, p2}, Llyiahf/vczjk/r43;-><init>(Llyiahf/vczjk/f43;Llyiahf/vczjk/bf3;Llyiahf/vczjk/yo1;)V

    iput-object p1, v0, Llyiahf/vczjk/r43;->L$0:Ljava/lang/Object;

    return-object v0
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    check-cast p1, Llyiahf/vczjk/h43;

    check-cast p2, Llyiahf/vczjk/yo1;

    invoke-virtual {p0, p1, p2}, Llyiahf/vczjk/r43;->create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/r43;

    sget-object p2, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    invoke-virtual {p1, p2}, Llyiahf/vczjk/r43;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    return-object p1
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 6

    sget-object v0, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    iget v1, p0, Llyiahf/vczjk/r43;->label:I

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

    iget-object p1, p0, Llyiahf/vczjk/r43;->L$0:Ljava/lang/Object;

    check-cast p1, Llyiahf/vczjk/h43;

    new-instance v1, Llyiahf/vczjk/hl7;

    invoke-direct {v1}, Ljava/lang/Object;-><init>()V

    sget-object v3, Llyiahf/vczjk/sb;->OooO0OO:Ljava/lang/Object;

    iput-object v3, v1, Llyiahf/vczjk/hl7;->element:Ljava/lang/Object;

    iget-object v3, p0, Llyiahf/vczjk/r43;->$this_simpleRunningReduce:Llyiahf/vczjk/f43;

    new-instance v4, Llyiahf/vczjk/q43;

    iget-object v5, p0, Llyiahf/vczjk/r43;->$operation:Llyiahf/vczjk/bf3;

    invoke-direct {v4, v1, v5, p1}, Llyiahf/vczjk/q43;-><init>(Llyiahf/vczjk/hl7;Llyiahf/vczjk/bf3;Llyiahf/vczjk/h43;)V

    iput v2, p0, Llyiahf/vczjk/r43;->label:I

    invoke-interface {v3, v4, p0}, Llyiahf/vczjk/f43;->OooO00o(Llyiahf/vczjk/h43;Llyiahf/vczjk/yo1;)Ljava/lang/Object;

    move-result-object p1

    if-ne p1, v0, :cond_2

    return-object v0

    :cond_2
    :goto_0
    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method
