.class public final synthetic Llyiahf/vczjk/nf4;
.super Llyiahf/vczjk/wf3;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# static fields
.field public static final OooOOO:Llyiahf/vczjk/nf4;


# direct methods
.method static constructor <clinit>()V
    .locals 6

    new-instance v0, Llyiahf/vczjk/nf4;

    const-string v4, "loadProperty(Lorg/jetbrains/kotlin/metadata/ProtoBuf$Property;)Lorg/jetbrains/kotlin/descriptors/PropertyDescriptor;"

    const/4 v5, 0x0

    const/4 v1, 0x2

    const-class v2, Llyiahf/vczjk/cg5;

    const-string v3, "loadProperty"

    invoke-direct/range {v0 .. v5}, Llyiahf/vczjk/wf3;-><init>(ILjava/lang/Class;Ljava/lang/String;Ljava/lang/String;I)V

    sput-object v0, Llyiahf/vczjk/nf4;->OooOOO:Llyiahf/vczjk/nf4;

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    check-cast p1, Llyiahf/vczjk/cg5;

    check-cast p2, Llyiahf/vczjk/xc7;

    const-string v0, "p0"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "p1"

    invoke-static {p2, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-virtual {p1, p2}, Llyiahf/vczjk/cg5;->OooO0o(Llyiahf/vczjk/xc7;)Llyiahf/vczjk/t82;

    move-result-object p1

    return-object p1
.end method
