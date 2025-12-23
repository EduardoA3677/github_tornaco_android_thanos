.class public final Llyiahf/vczjk/to6;
.super Llyiahf/vczjk/vo6;
.source "SourceFile"


# static fields
.field public static final OooO0O0:Llyiahf/vczjk/to6;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    new-instance v0, Llyiahf/vczjk/to6;

    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    sput-object v0, Llyiahf/vczjk/to6;->OooO0O0:Llyiahf/vczjk/to6;

    return-void
.end method


# virtual methods
.method public final OooO0O0(Llyiahf/vczjk/dr7;Ljava/lang/Object;)V
    .locals 0

    check-cast p2, Llyiahf/vczjk/ar5;

    if-eqz p2, :cond_0

    iget-object p1, p1, Llyiahf/vczjk/dr7;->OooO:Llyiahf/vczjk/ed5;

    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    iget-object p1, p1, Llyiahf/vczjk/ed5;->OooOOO:Ljava/lang/Object;

    check-cast p1, Ljava/util/ArrayList;

    invoke-virtual {p1, p2}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    :cond_0
    return-void
.end method
