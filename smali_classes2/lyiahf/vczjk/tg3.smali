.class public final Llyiahf/vczjk/tg3;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Ljava/lang/Comparable;


# instance fields
.field public final OooOOO:Llyiahf/vczjk/upa;

.field public final OooOOO0:I

.field public final OooOOOO:Z


# direct methods
.method public constructor <init>(ILlyiahf/vczjk/upa;Z)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput p1, p0, Llyiahf/vczjk/tg3;->OooOOO0:I

    iput-object p2, p0, Llyiahf/vczjk/tg3;->OooOOO:Llyiahf/vczjk/upa;

    iput-boolean p3, p0, Llyiahf/vczjk/tg3;->OooOOOO:Z

    return-void
.end method


# virtual methods
.method public final compareTo(Ljava/lang/Object;)I
    .locals 1

    check-cast p1, Llyiahf/vczjk/tg3;

    iget v0, p0, Llyiahf/vczjk/tg3;->OooOOO0:I

    iget p1, p1, Llyiahf/vczjk/tg3;->OooOOO0:I

    sub-int/2addr v0, p1

    return v0
.end method
