.class public final Llyiahf/vczjk/i8;
.super Llyiahf/vczjk/eb9;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/oe3;


# instance fields
.field final synthetic $block:Llyiahf/vczjk/bf3;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/bf3;"
        }
    .end annotation
.end field

.field label:I

.field final synthetic this$0:Llyiahf/vczjk/c9;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/c9;"
        }
    .end annotation
.end field


# direct methods
.method public constructor <init>(Llyiahf/vczjk/c9;Llyiahf/vczjk/yo1;Llyiahf/vczjk/bf3;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/i8;->this$0:Llyiahf/vczjk/c9;

    iput-object p3, p0, Llyiahf/vczjk/i8;->$block:Llyiahf/vczjk/bf3;

    const/4 p1, 0x1

    invoke-direct {p0, p1, p2}, Llyiahf/vczjk/eb9;-><init>(ILlyiahf/vczjk/yo1;)V

    return-void
.end method


# virtual methods
.method public final OooO0o(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    check-cast p1, Llyiahf/vczjk/yo1;

    invoke-virtual {p0, p1}, Llyiahf/vczjk/i8;->create(Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/i8;

    sget-object v0, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    invoke-virtual {p1, v0}, Llyiahf/vczjk/i8;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    return-object p1
.end method

.method public final create(Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;
    .locals 3

    new-instance v0, Llyiahf/vczjk/i8;

    iget-object v1, p0, Llyiahf/vczjk/i8;->this$0:Llyiahf/vczjk/c9;

    iget-object v2, p0, Llyiahf/vczjk/i8;->$block:Llyiahf/vczjk/bf3;

    invoke-direct {v0, v1, p1, v2}, Llyiahf/vczjk/i8;-><init>(Llyiahf/vczjk/c9;Llyiahf/vczjk/yo1;Llyiahf/vczjk/bf3;)V

    return-object v0
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 6

    sget-object v0, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    iget v1, p0, Llyiahf/vczjk/i8;->label:I

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

    iget-object p1, p0, Llyiahf/vczjk/i8;->this$0:Llyiahf/vczjk/c9;

    new-instance v1, Llyiahf/vczjk/c8;

    const/4 v3, 0x3

    invoke-direct {v1, p1, v3}, Llyiahf/vczjk/c8;-><init>(Llyiahf/vczjk/c9;I)V

    new-instance v3, Llyiahf/vczjk/g8;

    iget-object v4, p0, Llyiahf/vczjk/i8;->$block:Llyiahf/vczjk/bf3;

    const/4 v5, 0x0

    invoke-direct {v3, p1, v5, v4}, Llyiahf/vczjk/g8;-><init>(Llyiahf/vczjk/c9;Llyiahf/vczjk/yo1;Llyiahf/vczjk/bf3;)V

    iput v2, p0, Llyiahf/vczjk/i8;->label:I

    invoke-static {v1, v3, p0}, Landroidx/compose/material3/internal/OooO0O0;->OooO00o(Llyiahf/vczjk/le3;Llyiahf/vczjk/ze3;Llyiahf/vczjk/zo1;)Ljava/lang/Object;

    move-result-object p1

    if-ne p1, v0, :cond_2

    return-object v0

    :cond_2
    :goto_0
    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method
