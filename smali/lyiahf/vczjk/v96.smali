.class public final Llyiahf/vczjk/v96;
.super Llyiahf/vczjk/eb9;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/bf3;


# instance fields
.field final synthetic $completed:Llyiahf/vczjk/dl7;

.field label:I


# direct methods
.method public constructor <init>(Llyiahf/vczjk/dl7;Llyiahf/vczjk/yo1;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/v96;->$completed:Llyiahf/vczjk/dl7;

    const/4 p1, 0x3

    invoke-direct {p0, p1, p2}, Llyiahf/vczjk/eb9;-><init>(ILlyiahf/vczjk/yo1;)V

    return-void
.end method


# virtual methods
.method public final OooO0o0(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    check-cast p1, Llyiahf/vczjk/h43;

    check-cast p2, Ljava/lang/Throwable;

    check-cast p3, Llyiahf/vczjk/yo1;

    new-instance p1, Llyiahf/vczjk/v96;

    iget-object p2, p0, Llyiahf/vczjk/v96;->$completed:Llyiahf/vczjk/dl7;

    invoke-direct {p1, p2, p3}, Llyiahf/vczjk/v96;-><init>(Llyiahf/vczjk/dl7;Llyiahf/vczjk/yo1;)V

    sget-object p2, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    invoke-virtual {p1, p2}, Llyiahf/vczjk/v96;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    return-object p2
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    sget-object v0, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    iget v0, p0, Llyiahf/vczjk/v96;->label:I

    if-nez v0, :cond_0

    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    iget-object p1, p0, Llyiahf/vczjk/v96;->$completed:Llyiahf/vczjk/dl7;

    const/4 v0, 0x1

    iput-boolean v0, p1, Llyiahf/vczjk/dl7;->element:Z

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1

    :cond_0
    new-instance p1, Ljava/lang/IllegalStateException;

    const-string v0, "call to \'resume\' before \'invoke\' with coroutine"

    invoke-direct {p1, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p1
.end method
