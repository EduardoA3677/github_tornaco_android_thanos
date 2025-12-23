.class public abstract Llyiahf/vczjk/wr2;
.super Ljava/lang/Object;
.source "SourceFile"


# static fields
.field public static final OooO00o:Llyiahf/vczjk/d59;

.field public static final OooO0O0:Llyiahf/vczjk/d59;

.field public static final OooO0OO:Llyiahf/vczjk/d59;

.field public static final OooO0Oo:Llyiahf/vczjk/d59;

.field public static final OooO0o:Llyiahf/vczjk/d59;

.field public static final OooO0o0:Llyiahf/vczjk/d59;

.field public static final OooO0oO:Llyiahf/vczjk/d59;

.field public static final OooO0oo:Llyiahf/vczjk/d59;


# direct methods
.method static constructor <clinit>()V
    .locals 9

    const-string v0, "Ljava/lang/ArithmeticException;"

    invoke-static {v0}, Llyiahf/vczjk/p1a;->OooO0o(Ljava/lang/String;)Llyiahf/vczjk/p1a;

    move-result-object v0

    const-string v1, "Ljava/lang/ArrayIndexOutOfBoundsException;"

    invoke-static {v1}, Llyiahf/vczjk/p1a;->OooO0o(Ljava/lang/String;)Llyiahf/vczjk/p1a;

    move-result-object v1

    const-string v2, "Ljava/lang/ArrayStoreException;"

    invoke-static {v2}, Llyiahf/vczjk/p1a;->OooO0o(Ljava/lang/String;)Llyiahf/vczjk/p1a;

    move-result-object v2

    const-string v3, "Ljava/lang/ClassCastException;"

    invoke-static {v3}, Llyiahf/vczjk/p1a;->OooO0o(Ljava/lang/String;)Llyiahf/vczjk/p1a;

    move-result-object v3

    const-string v4, "Ljava/lang/Error;"

    invoke-static {v4}, Llyiahf/vczjk/p1a;->OooO0o(Ljava/lang/String;)Llyiahf/vczjk/p1a;

    move-result-object v4

    const-string v5, "Ljava/lang/IllegalMonitorStateException;"

    invoke-static {v5}, Llyiahf/vczjk/p1a;->OooO0o(Ljava/lang/String;)Llyiahf/vczjk/p1a;

    move-result-object v5

    const-string v6, "Ljava/lang/NegativeArraySizeException;"

    invoke-static {v6}, Llyiahf/vczjk/p1a;->OooO0o(Ljava/lang/String;)Llyiahf/vczjk/p1a;

    move-result-object v6

    const-string v7, "Ljava/lang/NullPointerException;"

    invoke-static {v7}, Llyiahf/vczjk/p1a;->OooO0o(Ljava/lang/String;)Llyiahf/vczjk/p1a;

    move-result-object v7

    invoke-static {v4}, Llyiahf/vczjk/d59;->OooO0oo(Llyiahf/vczjk/p1a;)Llyiahf/vczjk/d59;

    move-result-object v8

    sput-object v8, Llyiahf/vczjk/wr2;->OooO00o:Llyiahf/vczjk/d59;

    invoke-static {v4, v0}, Llyiahf/vczjk/d59;->OooO(Llyiahf/vczjk/p1a;Llyiahf/vczjk/p1a;)Llyiahf/vczjk/d59;

    move-result-object v0

    sput-object v0, Llyiahf/vczjk/wr2;->OooO0O0:Llyiahf/vczjk/d59;

    invoke-static {v4, v3}, Llyiahf/vczjk/d59;->OooO(Llyiahf/vczjk/p1a;Llyiahf/vczjk/p1a;)Llyiahf/vczjk/d59;

    move-result-object v0

    sput-object v0, Llyiahf/vczjk/wr2;->OooO0OO:Llyiahf/vczjk/d59;

    invoke-static {v4, v6}, Llyiahf/vczjk/d59;->OooO(Llyiahf/vczjk/p1a;Llyiahf/vczjk/p1a;)Llyiahf/vczjk/d59;

    move-result-object v0

    sput-object v0, Llyiahf/vczjk/wr2;->OooO0Oo:Llyiahf/vczjk/d59;

    invoke-static {v4, v7}, Llyiahf/vczjk/d59;->OooO(Llyiahf/vczjk/p1a;Llyiahf/vczjk/p1a;)Llyiahf/vczjk/d59;

    move-result-object v0

    sput-object v0, Llyiahf/vczjk/wr2;->OooO0o0:Llyiahf/vczjk/d59;

    invoke-static {v4, v7, v1}, Llyiahf/vczjk/d59;->OooOO0(Llyiahf/vczjk/p1a;Llyiahf/vczjk/p1a;Llyiahf/vczjk/p1a;)Llyiahf/vczjk/d59;

    move-result-object v0

    sput-object v0, Llyiahf/vczjk/wr2;->OooO0o:Llyiahf/vczjk/d59;

    new-instance v0, Llyiahf/vczjk/d59;

    const/4 v3, 0x4

    invoke-direct {v0, v3}, Llyiahf/vczjk/x13;-><init>(I)V

    const/4 v3, 0x0

    invoke-virtual {v0, v3, v4}, Llyiahf/vczjk/x13;->OooO0o(ILjava/lang/Object;)V

    const/4 v3, 0x1

    invoke-virtual {v0, v3, v7}, Llyiahf/vczjk/x13;->OooO0o(ILjava/lang/Object;)V

    const/4 v3, 0x2

    invoke-virtual {v0, v3, v1}, Llyiahf/vczjk/x13;->OooO0o(ILjava/lang/Object;)V

    const/4 v1, 0x3

    invoke-virtual {v0, v1, v2}, Llyiahf/vczjk/x13;->OooO0o(ILjava/lang/Object;)V

    sput-object v0, Llyiahf/vczjk/wr2;->OooO0oO:Llyiahf/vczjk/d59;

    invoke-static {v4, v7, v5}, Llyiahf/vczjk/d59;->OooOO0(Llyiahf/vczjk/p1a;Llyiahf/vczjk/p1a;Llyiahf/vczjk/p1a;)Llyiahf/vczjk/d59;

    move-result-object v0

    sput-object v0, Llyiahf/vczjk/wr2;->OooO0oo:Llyiahf/vczjk/d59;

    return-void
.end method
