.class public final Llyiahf/vczjk/o77;
.super Llyiahf/vczjk/zo1;
.source "SourceFile"


# instance fields
.field L$0:Ljava/lang/Object;

.field L$1:Ljava/lang/Object;

.field label:I

.field synthetic result:Ljava/lang/Object;


# virtual methods
.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    iput-object p1, p0, Llyiahf/vczjk/o77;->result:Ljava/lang/Object;

    iget p1, p0, Llyiahf/vczjk/o77;->label:I

    const/high16 v0, -0x80000000

    or-int/2addr p1, v0

    iput p1, p0, Llyiahf/vczjk/o77;->label:I

    const/4 p1, 0x0

    invoke-static {p1, p1, p0}, Llyiahf/vczjk/v34;->OooOOo(Llyiahf/vczjk/s77;Llyiahf/vczjk/le3;Llyiahf/vczjk/zo1;)Ljava/lang/Object;

    move-result-object p1

    return-object p1
.end method
