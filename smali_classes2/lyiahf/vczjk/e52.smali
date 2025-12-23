.class public final Llyiahf/vczjk/e52;
.super Llyiahf/vczjk/zo1;
.source "SourceFile"


# instance fields
.field label:I

.field synthetic result:Ljava/lang/Object;


# virtual methods
.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    iput-object p1, p0, Llyiahf/vczjk/e52;->result:Ljava/lang/Object;

    iget p1, p0, Llyiahf/vczjk/e52;->label:I

    const/high16 v0, -0x80000000

    or-int/2addr p1, v0

    iput p1, p0, Llyiahf/vczjk/e52;->label:I

    invoke-static {p0}, Llyiahf/vczjk/yi4;->OooOooO(Llyiahf/vczjk/zo1;)V

    sget-object p1, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    return-object p1
.end method
