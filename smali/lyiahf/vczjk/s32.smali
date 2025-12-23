.class public final Llyiahf/vczjk/s32;
.super Llyiahf/vczjk/eb9;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field final synthetic $block:Llyiahf/vczjk/ze3;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/ze3;"
        }
    .end annotation
.end field

.field final synthetic $scrollPriority:Llyiahf/vczjk/at5;

.field label:I

.field final synthetic this$0:Llyiahf/vczjk/u32;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/u32;Llyiahf/vczjk/at5;Llyiahf/vczjk/ze3;Llyiahf/vczjk/yo1;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/s32;->this$0:Llyiahf/vczjk/u32;

    iput-object p2, p0, Llyiahf/vczjk/s32;->$scrollPriority:Llyiahf/vczjk/at5;

    iput-object p3, p0, Llyiahf/vczjk/s32;->$block:Llyiahf/vczjk/ze3;

    const/4 p1, 0x2

    invoke-direct {p0, p1, p4}, Llyiahf/vczjk/eb9;-><init>(ILlyiahf/vczjk/yo1;)V

    return-void
.end method


# virtual methods
.method public final create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;
    .locals 3

    new-instance p1, Llyiahf/vczjk/s32;

    iget-object v0, p0, Llyiahf/vczjk/s32;->this$0:Llyiahf/vczjk/u32;

    iget-object v1, p0, Llyiahf/vczjk/s32;->$scrollPriority:Llyiahf/vczjk/at5;

    iget-object v2, p0, Llyiahf/vczjk/s32;->$block:Llyiahf/vczjk/ze3;

    invoke-direct {p1, v0, v1, v2, p2}, Llyiahf/vczjk/s32;-><init>(Llyiahf/vczjk/u32;Llyiahf/vczjk/at5;Llyiahf/vczjk/ze3;Llyiahf/vczjk/yo1;)V

    return-object p1
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    check-cast p1, Llyiahf/vczjk/xr1;

    check-cast p2, Llyiahf/vczjk/yo1;

    invoke-virtual {p0, p1, p2}, Llyiahf/vczjk/s32;->create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/s32;

    sget-object p2, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    invoke-virtual {p1, p2}, Llyiahf/vczjk/s32;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    return-object p1
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 9

    sget-object v0, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    iget v1, p0, Llyiahf/vczjk/s32;->label:I

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

    iget-object p1, p0, Llyiahf/vczjk/s32;->this$0:Llyiahf/vczjk/u32;

    iget-object v5, p1, Llyiahf/vczjk/u32;->OooO0OO:Llyiahf/vczjk/ht5;

    iget-object v7, p1, Llyiahf/vczjk/u32;->OooO0O0:Llyiahf/vczjk/t32;

    iget-object v4, p0, Llyiahf/vczjk/s32;->$scrollPriority:Llyiahf/vczjk/at5;

    new-instance v6, Llyiahf/vczjk/r32;

    iget-object v1, p0, Llyiahf/vczjk/s32;->$block:Llyiahf/vczjk/ze3;

    const/4 v3, 0x0

    invoke-direct {v6, p1, v1, v3}, Llyiahf/vczjk/r32;-><init>(Llyiahf/vczjk/u32;Llyiahf/vczjk/ze3;Llyiahf/vczjk/yo1;)V

    iput v2, p0, Llyiahf/vczjk/s32;->label:I

    invoke-virtual {v5}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    new-instance v3, Llyiahf/vczjk/gt5;

    const/4 v8, 0x0

    invoke-direct/range {v3 .. v8}, Llyiahf/vczjk/gt5;-><init>(Llyiahf/vczjk/at5;Llyiahf/vczjk/ht5;Llyiahf/vczjk/ze3;Ljava/lang/Object;Llyiahf/vczjk/yo1;)V

    invoke-static {v3, p0}, Llyiahf/vczjk/v34;->Oooo00O(Llyiahf/vczjk/ze3;Llyiahf/vczjk/yo1;)Ljava/lang/Object;

    move-result-object p1

    if-ne p1, v0, :cond_2

    return-object v0

    :cond_2
    :goto_0
    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method
