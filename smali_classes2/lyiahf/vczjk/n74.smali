.class public final Llyiahf/vczjk/n74;
.super Llyiahf/vczjk/oO0Oo0oo;
.source "SourceFile"


# static fields
.field public static final OooOOOo:Llyiahf/vczjk/n74;


# direct methods
.method static constructor <clinit>()V
    .locals 3

    new-instance v0, Llyiahf/vczjk/n74;

    const-string v1, "package"

    const/4 v2, 0x0

    invoke-direct {v0, v1, v2}, Llyiahf/vczjk/oO0Oo0oo;-><init>(Ljava/lang/String;Z)V

    sput-object v0, Llyiahf/vczjk/n74;->OooOOOo:Llyiahf/vczjk/n74;

    return-void
.end method


# virtual methods
.method public final OooO00o(Llyiahf/vczjk/oO0Oo0oo;)Ljava/lang/Integer;
    .locals 1

    const-string v0, "visibility"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    if-ne p0, p1, :cond_0

    const/4 p1, 0x0

    invoke-static {p1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object p1

    return-object p1

    :cond_0
    sget-object v0, Llyiahf/vczjk/bka;->OooO00o:Llyiahf/vczjk/eb5;

    sget-object v0, Llyiahf/vczjk/wja;->OooOOOo:Llyiahf/vczjk/wja;

    if-eq p1, v0, :cond_2

    sget-object v0, Llyiahf/vczjk/xja;->OooOOOo:Llyiahf/vczjk/xja;

    if-ne p1, v0, :cond_1

    goto :goto_0

    :cond_1
    const/4 p1, -0x1

    invoke-static {p1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object p1

    return-object p1

    :cond_2
    :goto_0
    const/4 p1, 0x1

    invoke-static {p1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object p1

    return-object p1
.end method

.method public final OooO0Oo()Ljava/lang/String;
    .locals 1

    const-string v0, "public/*package*/"

    return-object v0
.end method

.method public final OooOO0O()Llyiahf/vczjk/oO0Oo0oo;
    .locals 1

    sget-object v0, Llyiahf/vczjk/yja;->OooOOOo:Llyiahf/vczjk/yja;

    return-object v0
.end method
