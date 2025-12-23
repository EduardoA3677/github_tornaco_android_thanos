.class public final Llyiahf/vczjk/n48;
.super Llyiahf/vczjk/zo1;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/h43;


# instance fields
.field public final collectContext:Llyiahf/vczjk/or1;

.field public final collectContextSize:I

.field public final collector:Llyiahf/vczjk/h43;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/h43;"
        }
    .end annotation
.end field

.field private completion_:Llyiahf/vczjk/yo1;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/yo1<",
            "-",
            "Llyiahf/vczjk/z8a;",
            ">;"
        }
    .end annotation
.end field

.field private lastEmissionContext:Llyiahf/vczjk/or1;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/h43;Llyiahf/vczjk/or1;)V
    .locals 2

    sget-object v0, Llyiahf/vczjk/i61;->OooOOOO:Llyiahf/vczjk/i61;

    sget-object v1, Llyiahf/vczjk/wm2;->OooOOO0:Llyiahf/vczjk/wm2;

    invoke-direct {p0, v0, v1}, Llyiahf/vczjk/zo1;-><init>(Llyiahf/vczjk/yo1;Llyiahf/vczjk/or1;)V

    iput-object p1, p0, Llyiahf/vczjk/n48;->collector:Llyiahf/vczjk/h43;

    iput-object p2, p0, Llyiahf/vczjk/n48;->collectContext:Llyiahf/vczjk/or1;

    const/4 p1, 0x0

    invoke-static {p1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object p1

    new-instance v0, Llyiahf/vczjk/jm4;

    const/16 v1, 0x12

    invoke-direct {v0, v1}, Llyiahf/vczjk/jm4;-><init>(I)V

    invoke-interface {p2, p1, v0}, Llyiahf/vczjk/or1;->o000OOo(Ljava/lang/Object;Llyiahf/vczjk/ze3;)Ljava/lang/Object;

    move-result-object p1

    check-cast p1, Ljava/lang/Number;

    invoke-virtual {p1}, Ljava/lang/Number;->intValue()I

    move-result p1

    iput p1, p0, Llyiahf/vczjk/n48;->collectContextSize:I

    return-void
.end method


# virtual methods
.method public final OooOOO(Llyiahf/vczjk/yo1;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 4

    invoke-interface {p1}, Llyiahf/vczjk/yo1;->getContext()Llyiahf/vczjk/or1;

    move-result-object v0

    invoke-static {v0}, Llyiahf/vczjk/zsa;->Oooo0oo(Llyiahf/vczjk/or1;)V

    iget-object v1, p0, Llyiahf/vczjk/n48;->lastEmissionContext:Llyiahf/vczjk/or1;

    if-eq v1, v0, :cond_2

    instance-of v2, v1, Llyiahf/vczjk/vd2;

    if-nez v2, :cond_1

    const/4 v1, 0x0

    invoke-static {v1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v1

    new-instance v2, Llyiahf/vczjk/sj5;

    const/16 v3, 0x15

    invoke-direct {v2, p0, v3}, Llyiahf/vczjk/sj5;-><init>(Ljava/lang/Object;I)V

    invoke-interface {v0, v1, v2}, Llyiahf/vczjk/or1;->o000OOo(Ljava/lang/Object;Llyiahf/vczjk/ze3;)Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Ljava/lang/Number;

    invoke-virtual {v1}, Ljava/lang/Number;->intValue()I

    move-result v1

    iget v2, p0, Llyiahf/vczjk/n48;->collectContextSize:I

    if-ne v1, v2, :cond_0

    iput-object v0, p0, Llyiahf/vczjk/n48;->lastEmissionContext:Llyiahf/vczjk/or1;

    goto :goto_0

    :cond_0
    new-instance p1, Ljava/lang/IllegalStateException;

    new-instance p2, Ljava/lang/StringBuilder;

    const-string v1, "Flow invariant is violated:\n\t\tFlow was collected in "

    invoke-direct {p2, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    iget-object v1, p0, Llyiahf/vczjk/n48;->collectContext:Llyiahf/vczjk/or1;

    invoke-virtual {p2, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    const-string v1, ",\n\t\tbut emission happened in "

    invoke-virtual {p2, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {p2, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    const-string v0, ".\n\t\tPlease refer to \'flow\' documentation or use \'flowOn\' instead"

    invoke-virtual {p2, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {p2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object p2

    invoke-virtual {p2}, Ljava/lang/Object;->toString()Ljava/lang/String;

    move-result-object p2

    invoke-direct {p1, p2}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p1

    :cond_1
    check-cast v1, Llyiahf/vczjk/vd2;

    new-instance p1, Ljava/lang/IllegalStateException;

    new-instance v0, Ljava/lang/StringBuilder;

    const-string v2, "\n            Flow exception transparency is violated:\n                Previous \'emit\' call has thrown exception "

    invoke-direct {v0, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    iget-object v1, v1, Llyiahf/vczjk/vd2;->OooOOO:Ljava/lang/Throwable;

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    const-string v1, ", but then emission attempt of value \'"

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v0, p2}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    const-string p2, "\' has been detected.\n                Emissions from \'catch\' blocks are prohibited in order to avoid unspecified behaviour, \'Flow.catch\' operator can be used instead.\n                For a more detailed explanation, please refer to Flow documentation.\n            "

    invoke-virtual {v0, p2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object p2

    invoke-static {p2}, Llyiahf/vczjk/a79;->OooOoO0(Ljava/lang/String;)Ljava/lang/String;

    move-result-object p2

    invoke-virtual {p2}, Ljava/lang/Object;->toString()Ljava/lang/String;

    move-result-object p2

    invoke-direct {p1, p2}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p1

    :cond_2
    :goto_0
    iput-object p1, p0, Llyiahf/vczjk/n48;->completion_:Llyiahf/vczjk/yo1;

    sget-object p1, Llyiahf/vczjk/p48;->OooO00o:Llyiahf/vczjk/o48;

    iget-object v0, p0, Llyiahf/vczjk/n48;->collector:Llyiahf/vczjk/h43;

    const-string v1, "null cannot be cast to non-null type kotlinx.coroutines.flow.FlowCollector<kotlin.Any?>"

    invoke-static {v0, v1}, Llyiahf/vczjk/v34;->OooOo(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    invoke-interface {v0, p2, p0}, Llyiahf/vczjk/h43;->emit(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Ljava/lang/Object;

    move-result-object p1

    sget-object p2, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    invoke-static {p1, p2}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result p2

    if-nez p2, :cond_3

    const/4 p2, 0x0

    iput-object p2, p0, Llyiahf/vczjk/n48;->completion_:Llyiahf/vczjk/yo1;

    :cond_3
    return-object p1
.end method

.method public final emit(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Ljava/lang/Object;
    .locals 1

    :try_start_0
    invoke-virtual {p0, p2, p1}, Llyiahf/vczjk/n48;->OooOOO(Llyiahf/vczjk/yo1;Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    sget-object p2, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    if-ne p1, p2, :cond_0

    return-object p1

    :cond_0
    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1

    :catchall_0
    move-exception p1

    new-instance v0, Llyiahf/vczjk/vd2;

    invoke-interface {p2}, Llyiahf/vczjk/yo1;->getContext()Llyiahf/vczjk/or1;

    move-result-object p2

    invoke-direct {v0, p1, p2}, Llyiahf/vczjk/vd2;-><init>(Ljava/lang/Throwable;Llyiahf/vczjk/or1;)V

    iput-object v0, p0, Llyiahf/vczjk/n48;->lastEmissionContext:Llyiahf/vczjk/or1;

    throw p1
.end method

.method public final getCallerFrame()Llyiahf/vczjk/zr1;
    .locals 2

    iget-object v0, p0, Llyiahf/vczjk/n48;->completion_:Llyiahf/vczjk/yo1;

    instance-of v1, v0, Llyiahf/vczjk/zr1;

    if-eqz v1, :cond_0

    check-cast v0, Llyiahf/vczjk/zr1;

    return-object v0

    :cond_0
    const/4 v0, 0x0

    return-object v0
.end method

.method public final getContext()Llyiahf/vczjk/or1;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/n48;->lastEmissionContext:Llyiahf/vczjk/or1;

    if-nez v0, :cond_0

    sget-object v0, Llyiahf/vczjk/wm2;->OooOOO0:Llyiahf/vczjk/wm2;

    :cond_0
    return-object v0
.end method

.method public final getStackTraceElement()Ljava/lang/StackTraceElement;
    .locals 1

    const/4 v0, 0x0

    return-object v0
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 3

    invoke-static {p1}, Llyiahf/vczjk/vs7;->OooO00o(Ljava/lang/Object;)Ljava/lang/Throwable;

    move-result-object v0

    if-eqz v0, :cond_0

    new-instance v1, Llyiahf/vczjk/vd2;

    invoke-virtual {p0}, Llyiahf/vczjk/n48;->getContext()Llyiahf/vczjk/or1;

    move-result-object v2

    invoke-direct {v1, v0, v2}, Llyiahf/vczjk/vd2;-><init>(Ljava/lang/Throwable;Llyiahf/vczjk/or1;)V

    iput-object v1, p0, Llyiahf/vczjk/n48;->lastEmissionContext:Llyiahf/vczjk/or1;

    :cond_0
    iget-object v0, p0, Llyiahf/vczjk/n48;->completion_:Llyiahf/vczjk/yo1;

    if-eqz v0, :cond_1

    invoke-interface {v0, p1}, Llyiahf/vczjk/yo1;->resumeWith(Ljava/lang/Object;)V

    :cond_1
    sget-object p1, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    return-object p1
.end method
