.class public final Llyiahf/vczjk/dr8;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/cr8;


# static fields
.field public static final OooO00o:Llyiahf/vczjk/dr8;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    new-instance v0, Llyiahf/vczjk/dr8;

    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    sput-object v0, Llyiahf/vczjk/dr8;->OooO00o:Llyiahf/vczjk/dr8;

    return-void
.end method


# virtual methods
.method public final annotationType()Ljava/lang/Class;
    .locals 1

    const-class v0, Llyiahf/vczjk/cr8;

    return-object v0
.end method

.method public final equals(Ljava/lang/Object;)Z
    .locals 0

    instance-of p1, p1, Llyiahf/vczjk/cr8;

    return p1
.end method

.method public final hashCode()I
    .locals 1

    const/4 v0, 0x0

    return v0
.end method

.method public final toString()Ljava/lang/String;
    .locals 3

    new-instance v0, Ljava/lang/StringBuilder;

    const-string v1, "@"

    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    const-class v1, Llyiahf/vczjk/cr8;

    const-string v2, "()"

    invoke-static {v1, v0, v2}, Llyiahf/vczjk/ii5;->OooO0oo(Ljava/lang/Class;Ljava/lang/StringBuilder;Ljava/lang/String;)Ljava/lang/String;

    move-result-object v0

    return-object v0
.end method
