.class public final Llyiahf/vczjk/n86;
.super Ljava/lang/Object;
.source "SourceFile"


# instance fields
.field public final OooO00o:Llyiahf/vczjk/n62;

.field public final OooO0O0:[I

.field public final OooO0OO:[Ljava/lang/String;

.field public final OooO0Oo:Ljava/util/Set;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/n62;[I[Ljava/lang/String;)V
    .locals 1

    const-string v0, "observer"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "tableIds"

    invoke-static {p2, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "tableNames"

    invoke-static {p3, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/n86;->OooO00o:Llyiahf/vczjk/n62;

    iput-object p2, p0, Llyiahf/vczjk/n86;->OooO0O0:[I

    iput-object p3, p0, Llyiahf/vczjk/n86;->OooO0OO:[Ljava/lang/String;

    array-length p1, p2

    array-length p2, p3

    if-ne p1, p2, :cond_2

    array-length p1, p3

    const/4 p2, 0x0

    if-nez p1, :cond_0

    const/4 p1, 0x1

    goto :goto_0

    :cond_0
    move p1, p2

    :goto_0
    if-nez p1, :cond_1

    aget-object p1, p3, p2

    invoke-static {p1}, Llyiahf/vczjk/tp6;->Oooo0OO(Ljava/lang/Object;)Ljava/util/Set;

    move-result-object p1

    goto :goto_1

    :cond_1
    sget-object p1, Llyiahf/vczjk/gn2;->OooOOO0:Llyiahf/vczjk/gn2;

    :goto_1
    iput-object p1, p0, Llyiahf/vczjk/n86;->OooO0Oo:Ljava/util/Set;

    return-void

    :cond_2
    new-instance p1, Ljava/lang/IllegalStateException;

    const-string p2, "Check failed."

    invoke-direct {p1, p2}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p1
.end method
