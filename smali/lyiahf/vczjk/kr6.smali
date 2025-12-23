.class public final Llyiahf/vczjk/kr6;
.super Llyiahf/vczjk/nr6;
.source "SourceFile"


# instance fields
.field public final OooO0O0:Ljava/lang/String;

.field public final OooO0OO:Llyiahf/vczjk/jr6;


# direct methods
.method public constructor <init>(Ljava/lang/String;Ljava/lang/String;)V
    .locals 2

    invoke-direct {p0, p1}, Llyiahf/vczjk/nr6;-><init>(Ljava/lang/String;)V

    new-instance p1, Llyiahf/vczjk/jr6;

    invoke-direct {p1, p0}, Llyiahf/vczjk/jr6;-><init>(Llyiahf/vczjk/kr6;)V

    iput-object p1, p0, Llyiahf/vczjk/kr6;->OooO0OO:Llyiahf/vczjk/jr6;

    iput-object p2, p0, Llyiahf/vczjk/kr6;->OooO0O0:Ljava/lang/String;

    :try_start_0
    invoke-virtual {p1}, Ljava/lang/ThreadLocal;->get()Ljava/lang/Object;

    move-result-object p1

    check-cast p1, Ljava/text/SimpleDateFormat;

    new-instance v0, Ljava/util/Date;

    invoke-direct {v0}, Ljava/util/Date;-><init>()V

    invoke-virtual {p1, v0}, Ljava/text/DateFormat;->format(Ljava/util/Date;)Ljava/lang/String;
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    return-void

    :catch_0
    move-exception p1

    new-instance v0, Ljava/lang/IllegalArgumentException;

    const-string v1, "Bad date pattern: "

    invoke-static {v1, p2}, Llyiahf/vczjk/u81;->OooOo(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    move-result-object p2

    invoke-direct {v0, p2, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;Ljava/lang/Throwable;)V

    throw v0
.end method


# virtual methods
.method public final OooO00o(Ljava/lang/String;ILjava/lang/String;Ljava/lang/String;J)Ljava/lang/String;
    .locals 0

    iget-object p2, p0, Llyiahf/vczjk/kr6;->OooO0OO:Llyiahf/vczjk/jr6;

    invoke-virtual {p2}, Ljava/lang/ThreadLocal;->get()Ljava/lang/Object;

    move-result-object p2

    check-cast p2, Ljava/text/SimpleDateFormat;

    new-instance p3, Ljava/util/Date;

    invoke-direct {p3, p5, p6}, Ljava/util/Date;-><init>(J)V

    invoke-virtual {p2, p3}, Ljava/text/DateFormat;->format(Ljava/util/Date;)Ljava/lang/String;

    move-result-object p2

    iget-object p3, p0, Llyiahf/vczjk/nr6;->OooO00o:Ljava/lang/String;

    invoke-virtual {p1, p3, p2}, Ljava/lang/String;->replace(Ljava/lang/CharSequence;Ljava/lang/CharSequence;)Ljava/lang/String;

    move-result-object p1

    return-object p1
.end method
