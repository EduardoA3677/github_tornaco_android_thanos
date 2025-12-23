.class public final Llyiahf/vczjk/x34;
.super Llyiahf/vczjk/zo1;
.source "SourceFile"


# instance fields
.field final synthetic $receiver$inlined:Ljava/lang/Object;

.field final synthetic $this_createCoroutineUnintercepted$inlined:Llyiahf/vczjk/ze3;

.field private label:I


# direct methods
.method public constructor <init>(Llyiahf/vczjk/yo1;Llyiahf/vczjk/or1;Llyiahf/vczjk/ze3;Llyiahf/vczjk/yo1;)V
    .locals 0

    iput-object p3, p0, Llyiahf/vczjk/x34;->$this_createCoroutineUnintercepted$inlined:Llyiahf/vczjk/ze3;

    iput-object p4, p0, Llyiahf/vczjk/x34;->$receiver$inlined:Ljava/lang/Object;

    invoke-direct {p0, p1, p2}, Llyiahf/vczjk/zo1;-><init>(Llyiahf/vczjk/yo1;Llyiahf/vczjk/or1;)V

    return-void
.end method


# virtual methods
.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 3

    iget v0, p0, Llyiahf/vczjk/x34;->label:I

    const/4 v1, 0x2

    const/4 v2, 0x1

    if-eqz v0, :cond_1

    if-ne v0, v2, :cond_0

    iput v1, p0, Llyiahf/vczjk/x34;->label:I

    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    return-object p1

    :cond_0
    new-instance p1, Ljava/lang/IllegalStateException;

    const-string v0, "This coroutine had already completed"

    invoke-direct {p1, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p1

    :cond_1
    iput v2, p0, Llyiahf/vczjk/x34;->label:I

    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    iget-object p1, p0, Llyiahf/vczjk/x34;->$this_createCoroutineUnintercepted$inlined:Llyiahf/vczjk/ze3;

    const-string v0, "null cannot be cast to non-null type kotlin.Function2<R of kotlin.coroutines.intrinsics.IntrinsicsKt__IntrinsicsJvmKt.createCoroutineUnintercepted, kotlin.coroutines.Continuation<T of kotlin.coroutines.intrinsics.IntrinsicsKt__IntrinsicsJvmKt.createCoroutineUnintercepted>, kotlin.Any?>"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOo(Ljava/lang/Object;Ljava/lang/String;)V

    iget-object p1, p0, Llyiahf/vczjk/x34;->$this_createCoroutineUnintercepted$inlined:Llyiahf/vczjk/ze3;

    invoke-static {v1, p1}, Llyiahf/vczjk/l4a;->OooOO0(ILjava/lang/Object;)Ljava/lang/Object;

    iget-object v0, p0, Llyiahf/vczjk/x34;->$receiver$inlined:Ljava/lang/Object;

    invoke-interface {p1, v0, p0}, Llyiahf/vczjk/ze3;->invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    return-object p1
.end method
