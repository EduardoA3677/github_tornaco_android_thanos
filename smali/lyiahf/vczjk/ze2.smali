.class public final Llyiahf/vczjk/ze2;
.super Llyiahf/vczjk/eb9;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field final synthetic $onDrag:Llyiahf/vczjk/ze3;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/ze3;"
        }
    .end annotation
.end field

.field final synthetic $onDragCancel:Llyiahf/vczjk/le3;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/le3;"
        }
    .end annotation
.end field

.field final synthetic $onDragEnd:Llyiahf/vczjk/oe3;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/oe3;"
        }
    .end annotation
.end field

.field final synthetic $onDragStart:Llyiahf/vczjk/bf3;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/bf3;"
        }
    .end annotation
.end field

.field final synthetic $shouldAwaitTouchSlop:Llyiahf/vczjk/le3;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/le3;"
        }
    .end annotation
.end field

.field final synthetic $this_SuspendingPointerInputModifierNode:Llyiahf/vczjk/oy6;

.field private synthetic L$0:Ljava/lang/Object;

.field label:I

.field final synthetic this$0:Llyiahf/vczjk/kf2;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/kf2;Llyiahf/vczjk/oy6;Llyiahf/vczjk/bf3;Llyiahf/vczjk/oe3;Llyiahf/vczjk/le3;Llyiahf/vczjk/le3;Llyiahf/vczjk/ze3;Llyiahf/vczjk/yo1;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/ze2;->this$0:Llyiahf/vczjk/kf2;

    iput-object p2, p0, Llyiahf/vczjk/ze2;->$this_SuspendingPointerInputModifierNode:Llyiahf/vczjk/oy6;

    iput-object p3, p0, Llyiahf/vczjk/ze2;->$onDragStart:Llyiahf/vczjk/bf3;

    iput-object p4, p0, Llyiahf/vczjk/ze2;->$onDragEnd:Llyiahf/vczjk/oe3;

    iput-object p5, p0, Llyiahf/vczjk/ze2;->$onDragCancel:Llyiahf/vczjk/le3;

    iput-object p6, p0, Llyiahf/vczjk/ze2;->$shouldAwaitTouchSlop:Llyiahf/vczjk/le3;

    iput-object p7, p0, Llyiahf/vczjk/ze2;->$onDrag:Llyiahf/vczjk/ze3;

    const/4 p1, 0x2

    invoke-direct {p0, p1, p8}, Llyiahf/vczjk/eb9;-><init>(ILlyiahf/vczjk/yo1;)V

    return-void
.end method


# virtual methods
.method public final create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;
    .locals 9

    new-instance v0, Llyiahf/vczjk/ze2;

    iget-object v1, p0, Llyiahf/vczjk/ze2;->this$0:Llyiahf/vczjk/kf2;

    iget-object v2, p0, Llyiahf/vczjk/ze2;->$this_SuspendingPointerInputModifierNode:Llyiahf/vczjk/oy6;

    iget-object v3, p0, Llyiahf/vczjk/ze2;->$onDragStart:Llyiahf/vczjk/bf3;

    iget-object v4, p0, Llyiahf/vczjk/ze2;->$onDragEnd:Llyiahf/vczjk/oe3;

    iget-object v5, p0, Llyiahf/vczjk/ze2;->$onDragCancel:Llyiahf/vczjk/le3;

    iget-object v6, p0, Llyiahf/vczjk/ze2;->$shouldAwaitTouchSlop:Llyiahf/vczjk/le3;

    iget-object v7, p0, Llyiahf/vczjk/ze2;->$onDrag:Llyiahf/vczjk/ze3;

    move-object v8, p2

    invoke-direct/range {v0 .. v8}, Llyiahf/vczjk/ze2;-><init>(Llyiahf/vczjk/kf2;Llyiahf/vczjk/oy6;Llyiahf/vczjk/bf3;Llyiahf/vczjk/oe3;Llyiahf/vczjk/le3;Llyiahf/vczjk/le3;Llyiahf/vczjk/ze3;Llyiahf/vczjk/yo1;)V

    iput-object p1, v0, Llyiahf/vczjk/ze2;->L$0:Ljava/lang/Object;

    return-object v0
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    check-cast p1, Llyiahf/vczjk/xr1;

    check-cast p2, Llyiahf/vczjk/yo1;

    invoke-virtual {p0, p1, p2}, Llyiahf/vczjk/ze2;->create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/ze2;

    sget-object p2, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    invoke-virtual {p1, p2}, Llyiahf/vczjk/ze2;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    return-object p1
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 13

    sget-object v0, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    iget v1, p0, Llyiahf/vczjk/ze2;->label:I

    sget-object v2, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    const/4 v3, 0x1

    if-eqz v1, :cond_1

    if-ne v1, v3, :cond_0

    iget-object v0, p0, Llyiahf/vczjk/ze2;->L$0:Ljava/lang/Object;

    move-object v1, v0

    check-cast v1, Llyiahf/vczjk/xr1;

    :try_start_0
    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V
    :try_end_0
    .catch Ljava/util/concurrent/CancellationException; {:try_start_0 .. :try_end_0} :catch_0

    goto :goto_2

    :catch_0
    move-exception v0

    move-object p1, v0

    goto :goto_1

    :cond_0
    new-instance p1, Ljava/lang/IllegalStateException;

    const-string v0, "call to \'resume\' before \'invoke\' with coroutine"

    invoke-direct {p1, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p1

    :cond_1
    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    iget-object p1, p0, Llyiahf/vczjk/ze2;->L$0:Ljava/lang/Object;

    move-object v1, p1

    check-cast v1, Llyiahf/vczjk/xr1;

    :try_start_1
    iget-object p1, p0, Llyiahf/vczjk/ze2;->this$0:Llyiahf/vczjk/kf2;

    iget-object v7, p1, Llyiahf/vczjk/kf2;->OooOoo:Llyiahf/vczjk/nf6;

    iget-object p1, p0, Llyiahf/vczjk/ze2;->$this_SuspendingPointerInputModifierNode:Llyiahf/vczjk/oy6;

    iget-object v8, p0, Llyiahf/vczjk/ze2;->$onDragStart:Llyiahf/vczjk/bf3;

    iget-object v11, p0, Llyiahf/vczjk/ze2;->$onDragEnd:Llyiahf/vczjk/oe3;

    iget-object v10, p0, Llyiahf/vczjk/ze2;->$onDragCancel:Llyiahf/vczjk/le3;

    iget-object v5, p0, Llyiahf/vczjk/ze2;->$shouldAwaitTouchSlop:Llyiahf/vczjk/le3;

    iget-object v9, p0, Llyiahf/vczjk/ze2;->$onDrag:Llyiahf/vczjk/ze3;

    iput-object v1, p0, Llyiahf/vczjk/ze2;->L$0:Ljava/lang/Object;

    iput v3, p0, Llyiahf/vczjk/ze2;->label:I

    sget v3, Llyiahf/vczjk/ve2;->OooO00o:F

    new-instance v6, Llyiahf/vczjk/gl7;

    invoke-direct {v6}, Ljava/lang/Object;-><init>()V

    new-instance v4, Llyiahf/vczjk/te2;

    const/4 v12, 0x0

    invoke-direct/range {v4 .. v12}, Llyiahf/vczjk/te2;-><init>(Llyiahf/vczjk/le3;Llyiahf/vczjk/gl7;Llyiahf/vczjk/nf6;Llyiahf/vczjk/bf3;Llyiahf/vczjk/ze3;Llyiahf/vczjk/le3;Llyiahf/vczjk/oe3;Llyiahf/vczjk/yo1;)V

    invoke-static {p1, v4, p0}, Llyiahf/vczjk/u34;->OooO0o0(Llyiahf/vczjk/oy6;Llyiahf/vczjk/ze3;Llyiahf/vczjk/yo1;)Ljava/lang/Object;

    move-result-object p1
    :try_end_1
    .catch Ljava/util/concurrent/CancellationException; {:try_start_1 .. :try_end_1} :catch_0

    if-ne p1, v0, :cond_2

    goto :goto_0

    :cond_2
    move-object p1, v2

    :goto_0
    if-ne p1, v0, :cond_4

    return-object v0

    :goto_1
    iget-object v0, p0, Llyiahf/vczjk/ze2;->this$0:Llyiahf/vczjk/kf2;

    iget-object v0, v0, Llyiahf/vczjk/kf2;->Oooo00O:Llyiahf/vczjk/jj0;

    if-eqz v0, :cond_3

    sget-object v3, Llyiahf/vczjk/je2;->OooO00o:Llyiahf/vczjk/je2;

    invoke-interface {v0, v3}, Llyiahf/vczjk/if8;->OooO0oo(Ljava/lang/Object;)Ljava/lang/Object;

    :cond_3
    invoke-static {v1}, Llyiahf/vczjk/v34;->OoooOoO(Llyiahf/vczjk/xr1;)Z

    move-result v0

    if-eqz v0, :cond_5

    :cond_4
    :goto_2
    return-object v2

    :cond_5
    throw p1
.end method
