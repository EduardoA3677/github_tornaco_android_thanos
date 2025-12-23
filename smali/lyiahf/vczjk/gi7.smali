.class public final Llyiahf/vczjk/gi7;
.super Llyiahf/vczjk/eb9;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field final synthetic $eventListener:Llyiahf/vczjk/jr2;

.field final synthetic $placeholderBitmap:Landroid/graphics/Bitmap;

.field final synthetic $request:Llyiahf/vczjk/kv3;

.field final synthetic $size:Llyiahf/vczjk/sq8;

.field label:I

.field final synthetic this$0:Llyiahf/vczjk/ii7;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/kv3;Llyiahf/vczjk/ii7;Llyiahf/vczjk/sq8;Llyiahf/vczjk/jr2;Landroid/graphics/Bitmap;Llyiahf/vczjk/yo1;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/gi7;->$request:Llyiahf/vczjk/kv3;

    iput-object p2, p0, Llyiahf/vczjk/gi7;->this$0:Llyiahf/vczjk/ii7;

    iput-object p3, p0, Llyiahf/vczjk/gi7;->$size:Llyiahf/vczjk/sq8;

    iput-object p4, p0, Llyiahf/vczjk/gi7;->$eventListener:Llyiahf/vczjk/jr2;

    iput-object p5, p0, Llyiahf/vczjk/gi7;->$placeholderBitmap:Landroid/graphics/Bitmap;

    const/4 p1, 0x2

    invoke-direct {p0, p1, p6}, Llyiahf/vczjk/eb9;-><init>(ILlyiahf/vczjk/yo1;)V

    return-void
.end method


# virtual methods
.method public final create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;
    .locals 7

    new-instance v0, Llyiahf/vczjk/gi7;

    iget-object v1, p0, Llyiahf/vczjk/gi7;->$request:Llyiahf/vczjk/kv3;

    iget-object v2, p0, Llyiahf/vczjk/gi7;->this$0:Llyiahf/vczjk/ii7;

    iget-object v3, p0, Llyiahf/vczjk/gi7;->$size:Llyiahf/vczjk/sq8;

    iget-object v4, p0, Llyiahf/vczjk/gi7;->$eventListener:Llyiahf/vczjk/jr2;

    iget-object v5, p0, Llyiahf/vczjk/gi7;->$placeholderBitmap:Landroid/graphics/Bitmap;

    move-object v6, p2

    invoke-direct/range {v0 .. v6}, Llyiahf/vczjk/gi7;-><init>(Llyiahf/vczjk/kv3;Llyiahf/vczjk/ii7;Llyiahf/vczjk/sq8;Llyiahf/vczjk/jr2;Landroid/graphics/Bitmap;Llyiahf/vczjk/yo1;)V

    return-object v0
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    check-cast p1, Llyiahf/vczjk/xr1;

    check-cast p2, Llyiahf/vczjk/yo1;

    invoke-virtual {p0, p1, p2}, Llyiahf/vczjk/gi7;->create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/gi7;

    sget-object p2, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    invoke-virtual {p1, p2}, Llyiahf/vczjk/gi7;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    return-object p1
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 11

    sget-object v0, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    iget v1, p0, Llyiahf/vczjk/gi7;->label:I

    const/4 v2, 0x1

    if-eqz v1, :cond_1

    if-ne v1, v2, :cond_0

    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    return-object p1

    :cond_0
    new-instance p1, Ljava/lang/IllegalStateException;

    const-string v0, "call to \'resume\' before \'invoke\' with coroutine"

    invoke-direct {p1, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p1

    :cond_1
    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    new-instance v3, Llyiahf/vczjk/li7;

    iget-object v4, p0, Llyiahf/vczjk/gi7;->$request:Llyiahf/vczjk/kv3;

    iget-object p1, p0, Llyiahf/vczjk/gi7;->this$0:Llyiahf/vczjk/ii7;

    iget-object v5, p1, Llyiahf/vczjk/ii7;->OooO0oo:Ljava/util/ArrayList;

    iget-object v8, p0, Llyiahf/vczjk/gi7;->$size:Llyiahf/vczjk/sq8;

    iget-object v9, p0, Llyiahf/vczjk/gi7;->$eventListener:Llyiahf/vczjk/jr2;

    iget-object p1, p0, Llyiahf/vczjk/gi7;->$placeholderBitmap:Landroid/graphics/Bitmap;

    if-eqz p1, :cond_2

    move v10, v2

    goto :goto_0

    :cond_2
    const/4 p1, 0x0

    move v10, p1

    :goto_0
    const/4 v6, 0x0

    move-object v7, v4

    invoke-direct/range {v3 .. v10}, Llyiahf/vczjk/li7;-><init>(Llyiahf/vczjk/kv3;Ljava/util/ArrayList;ILlyiahf/vczjk/kv3;Llyiahf/vczjk/sq8;Llyiahf/vczjk/jr2;Z)V

    iput v2, p0, Llyiahf/vczjk/gi7;->label:I

    invoke-virtual {v3, v4, p0}, Llyiahf/vczjk/li7;->OooO0O0(Llyiahf/vczjk/kv3;Llyiahf/vczjk/zo1;)Ljava/lang/Object;

    move-result-object p1

    if-ne p1, v0, :cond_3

    return-object v0

    :cond_3
    return-object p1
.end method
