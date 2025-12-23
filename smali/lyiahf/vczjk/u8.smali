.class public final Llyiahf/vczjk/u8;
.super Llyiahf/vczjk/eb9;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/bf3;


# instance fields
.field final synthetic $block:Llyiahf/vczjk/ze3;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/ze3;"
        }
    .end annotation
.end field

.field label:I

.field final synthetic this$0:Llyiahf/vczjk/x8;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/x8;Llyiahf/vczjk/ze3;Llyiahf/vczjk/yo1;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/u8;->this$0:Llyiahf/vczjk/x8;

    iput-object p2, p0, Llyiahf/vczjk/u8;->$block:Llyiahf/vczjk/ze3;

    const/4 p1, 0x3

    invoke-direct {p0, p1, p3}, Llyiahf/vczjk/eb9;-><init>(ILlyiahf/vczjk/yo1;)V

    return-void
.end method


# virtual methods
.method public final OooO0o0(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    check-cast p1, Llyiahf/vczjk/r8;

    check-cast p2, Llyiahf/vczjk/kb5;

    check-cast p3, Llyiahf/vczjk/yo1;

    new-instance p1, Llyiahf/vczjk/u8;

    iget-object p2, p0, Llyiahf/vczjk/u8;->this$0:Llyiahf/vczjk/x8;

    iget-object v0, p0, Llyiahf/vczjk/u8;->$block:Llyiahf/vczjk/ze3;

    invoke-direct {p1, p2, v0, p3}, Llyiahf/vczjk/u8;-><init>(Llyiahf/vczjk/x8;Llyiahf/vczjk/ze3;Llyiahf/vczjk/yo1;)V

    sget-object p2, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    invoke-virtual {p1, p2}, Llyiahf/vczjk/u8;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    return-object p1
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 3

    sget-object v0, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    iget v1, p0, Llyiahf/vczjk/u8;->label:I

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

    iget-object p1, p0, Llyiahf/vczjk/u8;->this$0:Llyiahf/vczjk/x8;

    iget-object p1, p1, Llyiahf/vczjk/x8;->OooO00o:Llyiahf/vczjk/w8;

    iget-object v1, p0, Llyiahf/vczjk/u8;->$block:Llyiahf/vczjk/ze3;

    iput v2, p0, Llyiahf/vczjk/u8;->label:I

    invoke-interface {v1, p1, p0}, Llyiahf/vczjk/ze3;->invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    if-ne p1, v0, :cond_2

    return-object v0

    :cond_2
    :goto_0
    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method
