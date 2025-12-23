.class public final Llyiahf/vczjk/sn2;
.super Llyiahf/vczjk/eb9;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field final synthetic $components:Llyiahf/vczjk/hl7;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/hl7;"
        }
    .end annotation
.end field

.field final synthetic $eventListener:Llyiahf/vczjk/jr2;

.field final synthetic $fetchResult:Llyiahf/vczjk/hl7;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/hl7;"
        }
    .end annotation
.end field

.field final synthetic $mappedData:Ljava/lang/Object;

.field final synthetic $options:Llyiahf/vczjk/hl7;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/hl7;"
        }
    .end annotation
.end field

.field final synthetic $request:Llyiahf/vczjk/kv3;

.field label:I

.field final synthetic this$0:Llyiahf/vczjk/wn2;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/wn2;Llyiahf/vczjk/hl7;Llyiahf/vczjk/hl7;Llyiahf/vczjk/kv3;Ljava/lang/Object;Llyiahf/vczjk/hl7;Llyiahf/vczjk/jr2;Llyiahf/vczjk/yo1;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/sn2;->this$0:Llyiahf/vczjk/wn2;

    iput-object p2, p0, Llyiahf/vczjk/sn2;->$fetchResult:Llyiahf/vczjk/hl7;

    iput-object p3, p0, Llyiahf/vczjk/sn2;->$components:Llyiahf/vczjk/hl7;

    iput-object p4, p0, Llyiahf/vczjk/sn2;->$request:Llyiahf/vczjk/kv3;

    iput-object p5, p0, Llyiahf/vczjk/sn2;->$mappedData:Ljava/lang/Object;

    iput-object p6, p0, Llyiahf/vczjk/sn2;->$options:Llyiahf/vczjk/hl7;

    iput-object p7, p0, Llyiahf/vczjk/sn2;->$eventListener:Llyiahf/vczjk/jr2;

    const/4 p1, 0x2

    invoke-direct {p0, p1, p8}, Llyiahf/vczjk/eb9;-><init>(ILlyiahf/vczjk/yo1;)V

    return-void
.end method


# virtual methods
.method public final create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;
    .locals 9

    new-instance v0, Llyiahf/vczjk/sn2;

    iget-object v1, p0, Llyiahf/vczjk/sn2;->this$0:Llyiahf/vczjk/wn2;

    iget-object v2, p0, Llyiahf/vczjk/sn2;->$fetchResult:Llyiahf/vczjk/hl7;

    iget-object v3, p0, Llyiahf/vczjk/sn2;->$components:Llyiahf/vczjk/hl7;

    iget-object v4, p0, Llyiahf/vczjk/sn2;->$request:Llyiahf/vczjk/kv3;

    iget-object v5, p0, Llyiahf/vczjk/sn2;->$mappedData:Ljava/lang/Object;

    iget-object v6, p0, Llyiahf/vczjk/sn2;->$options:Llyiahf/vczjk/hl7;

    iget-object v7, p0, Llyiahf/vczjk/sn2;->$eventListener:Llyiahf/vczjk/jr2;

    move-object v8, p2

    invoke-direct/range {v0 .. v8}, Llyiahf/vczjk/sn2;-><init>(Llyiahf/vczjk/wn2;Llyiahf/vczjk/hl7;Llyiahf/vczjk/hl7;Llyiahf/vczjk/kv3;Ljava/lang/Object;Llyiahf/vczjk/hl7;Llyiahf/vczjk/jr2;Llyiahf/vczjk/yo1;)V

    return-object v0
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    check-cast p1, Llyiahf/vczjk/xr1;

    check-cast p2, Llyiahf/vczjk/yo1;

    invoke-virtual {p0, p1, p2}, Llyiahf/vczjk/sn2;->create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/sn2;

    sget-object p2, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    invoke-virtual {p1, p2}, Llyiahf/vczjk/sn2;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    return-object p1
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 9

    sget-object v0, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    iget v1, p0, Llyiahf/vczjk/sn2;->label:I

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

    iget-object v1, p0, Llyiahf/vczjk/sn2;->this$0:Llyiahf/vczjk/wn2;

    iget-object p1, p0, Llyiahf/vczjk/sn2;->$fetchResult:Llyiahf/vczjk/hl7;

    iget-object p1, p1, Llyiahf/vczjk/hl7;->element:Ljava/lang/Object;

    check-cast p1, Llyiahf/vczjk/by8;

    iget-object v3, p0, Llyiahf/vczjk/sn2;->$components:Llyiahf/vczjk/hl7;

    iget-object v3, v3, Llyiahf/vczjk/hl7;->element:Ljava/lang/Object;

    check-cast v3, Llyiahf/vczjk/f71;

    iget-object v4, p0, Llyiahf/vczjk/sn2;->$request:Llyiahf/vczjk/kv3;

    iget-object v5, p0, Llyiahf/vczjk/sn2;->$mappedData:Ljava/lang/Object;

    iget-object v6, p0, Llyiahf/vczjk/sn2;->$options:Llyiahf/vczjk/hl7;

    iget-object v6, v6, Llyiahf/vczjk/hl7;->element:Ljava/lang/Object;

    check-cast v6, Llyiahf/vczjk/hf6;

    iget-object v7, p0, Llyiahf/vczjk/sn2;->$eventListener:Llyiahf/vczjk/jr2;

    iput v2, p0, Llyiahf/vczjk/sn2;->label:I

    move-object v8, p0

    move-object v2, p1

    invoke-static/range {v1 .. v8}, Llyiahf/vczjk/wn2;->OooO00o(Llyiahf/vczjk/wn2;Llyiahf/vczjk/by8;Llyiahf/vczjk/f71;Llyiahf/vczjk/kv3;Ljava/lang/Object;Llyiahf/vczjk/hf6;Llyiahf/vczjk/jr2;Llyiahf/vczjk/zo1;)Ljava/lang/Object;

    move-result-object p1

    if-ne p1, v0, :cond_2

    return-object v0

    :cond_2
    return-object p1
.end method
