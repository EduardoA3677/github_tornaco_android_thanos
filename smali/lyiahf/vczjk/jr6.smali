.class public final Llyiahf/vczjk/jr6;
.super Ljava/lang/ThreadLocal;
.source "SourceFile"


# instance fields
.field public final synthetic OooO00o:Llyiahf/vczjk/kr6;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/kr6;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/jr6;->OooO00o:Llyiahf/vczjk/kr6;

    invoke-direct {p0}, Ljava/lang/ThreadLocal;-><init>()V

    return-void
.end method


# virtual methods
.method public final initialValue()Ljava/lang/Object;
    .locals 3

    new-instance v0, Ljava/text/SimpleDateFormat;

    iget-object v1, p0, Llyiahf/vczjk/jr6;->OooO00o:Llyiahf/vczjk/kr6;

    iget-object v1, v1, Llyiahf/vczjk/kr6;->OooO0O0:Ljava/lang/String;

    sget-object v2, Ljava/util/Locale;->US:Ljava/util/Locale;

    invoke-direct {v0, v1, v2}, Ljava/text/SimpleDateFormat;-><init>(Ljava/lang/String;Ljava/util/Locale;)V

    return-object v0
.end method
