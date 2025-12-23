.class public final Llyiahf/vczjk/ci;
.super Llyiahf/vczjk/eb9;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/oe3;


# instance fields
.field final synthetic $targetValue:Ljava/lang/Object;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/lang/Object;"
        }
    .end annotation
.end field

.field label:I

.field final synthetic this$0:Llyiahf/vczjk/gi;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/gi;"
        }
    .end annotation
.end field


# direct methods
.method public constructor <init>(Llyiahf/vczjk/gi;Ljava/lang/Object;Llyiahf/vczjk/yo1;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/ci;->this$0:Llyiahf/vczjk/gi;

    iput-object p2, p0, Llyiahf/vczjk/ci;->$targetValue:Ljava/lang/Object;

    const/4 p1, 0x1

    invoke-direct {p0, p1, p3}, Llyiahf/vczjk/eb9;-><init>(ILlyiahf/vczjk/yo1;)V

    return-void
.end method


# virtual methods
.method public final OooO0o(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    check-cast p1, Llyiahf/vczjk/yo1;

    invoke-virtual {p0, p1}, Llyiahf/vczjk/ci;->create(Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/ci;

    sget-object v0, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    invoke-virtual {p1, v0}, Llyiahf/vczjk/ci;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    return-object v0
.end method

.method public final create(Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;
    .locals 3

    new-instance v0, Llyiahf/vczjk/ci;

    iget-object v1, p0, Llyiahf/vczjk/ci;->this$0:Llyiahf/vczjk/gi;

    iget-object v2, p0, Llyiahf/vczjk/ci;->$targetValue:Ljava/lang/Object;

    invoke-direct {v0, v1, v2, p1}, Llyiahf/vczjk/ci;-><init>(Llyiahf/vczjk/gi;Ljava/lang/Object;Llyiahf/vczjk/yo1;)V

    return-object v0
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    sget-object v0, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    iget v0, p0, Llyiahf/vczjk/ci;->label:I

    if-nez v0, :cond_0

    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    iget-object p1, p0, Llyiahf/vczjk/ci;->this$0:Llyiahf/vczjk/gi;

    invoke-static {p1}, Llyiahf/vczjk/gi;->OooO00o(Llyiahf/vczjk/gi;)V

    iget-object p1, p0, Llyiahf/vczjk/ci;->this$0:Llyiahf/vczjk/gi;

    iget-object v0, p0, Llyiahf/vczjk/ci;->$targetValue:Ljava/lang/Object;

    invoke-virtual {p1, v0}, Llyiahf/vczjk/gi;->OooO0OO(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    iget-object v0, p0, Llyiahf/vczjk/ci;->this$0:Llyiahf/vczjk/gi;

    iget-object v0, v0, Llyiahf/vczjk/gi;->OooO0OO:Llyiahf/vczjk/xl;

    iget-object v0, v0, Llyiahf/vczjk/xl;->OooOOO:Llyiahf/vczjk/qs5;

    check-cast v0, Llyiahf/vczjk/fw8;

    invoke-virtual {v0, p1}, Llyiahf/vczjk/fw8;->setValue(Ljava/lang/Object;)V

    iget-object v0, p0, Llyiahf/vczjk/ci;->this$0:Llyiahf/vczjk/gi;

    iget-object v0, v0, Llyiahf/vczjk/gi;->OooO0o0:Llyiahf/vczjk/qs5;

    check-cast v0, Llyiahf/vczjk/fw8;

    invoke-virtual {v0, p1}, Llyiahf/vczjk/fw8;->setValue(Ljava/lang/Object;)V

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1

    :cond_0
    new-instance p1, Ljava/lang/IllegalStateException;

    const-string v0, "call to \'resume\' before \'invoke\' with coroutine"

    invoke-direct {p1, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p1
.end method
