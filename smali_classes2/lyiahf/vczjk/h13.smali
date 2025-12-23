.class public final synthetic Llyiahf/vczjk/h13;
.super Llyiahf/vczjk/za7;
.source "SourceFile"


# static fields
.field public static final OooOOO:Llyiahf/vczjk/h13;


# direct methods
.method static constructor <clinit>()V
    .locals 5

    new-instance v0, Llyiahf/vczjk/h13;

    const-string v1, "getOuterClassId()Lorg/jetbrains/kotlin/name/ClassId;"

    const/4 v2, 0x0

    const-class v3, Llyiahf/vczjk/hy0;

    const-string v4, "outerClassId"

    invoke-direct {v0, v3, v4, v1, v2}, Llyiahf/vczjk/za7;-><init>(Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;I)V

    sput-object v0, Llyiahf/vczjk/h13;->OooOOO:Llyiahf/vczjk/h13;

    return-void
.end method


# virtual methods
.method public final get(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    check-cast p1, Llyiahf/vczjk/hy0;

    invoke-virtual {p1}, Llyiahf/vczjk/hy0;->OooO0o0()Llyiahf/vczjk/hy0;

    move-result-object p1

    return-object p1
.end method
