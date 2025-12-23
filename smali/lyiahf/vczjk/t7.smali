.class public final Llyiahf/vczjk/t7;
.super Llyiahf/vczjk/zo1;
.source "SourceFile"


# instance fields
.field label:I

.field synthetic result:Ljava/lang/Object;


# virtual methods
.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    iput-object p1, p0, Llyiahf/vczjk/t7;->result:Ljava/lang/Object;

    iget p1, p0, Llyiahf/vczjk/t7;->label:I

    const/high16 v0, -0x80000000

    or-int/2addr p1, v0

    iput p1, p0, Llyiahf/vczjk/t7;->label:I

    const/4 p1, 0x0

    invoke-static {p1, p1, p0}, Llyiahf/vczjk/t51;->OooOO0O(Llyiahf/vczjk/le3;Llyiahf/vczjk/ze3;Llyiahf/vczjk/zo1;)Ljava/lang/Object;

    move-result-object p1

    return-object p1
.end method
