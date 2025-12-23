.class public abstract Llyiahf/vczjk/xh4;
.super Llyiahf/vczjk/vh4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/fh4;


# static fields
.field public static final synthetic OooOOo0:[Llyiahf/vczjk/th4;


# instance fields
.field public final OooOOOO:Llyiahf/vczjk/wm7;

.field public final OooOOOo:Ljava/lang/Object;


# direct methods
.method static constructor <clinit>()V
    .locals 5

    new-instance v0, Llyiahf/vczjk/za7;

    const-class v1, Llyiahf/vczjk/xh4;

    const-string v2, "descriptor"

    const-string v3, "getDescriptor()Lorg/jetbrains/kotlin/descriptors/PropertyGetterDescriptor;"

    const/4 v4, 0x0

    invoke-direct {v0, v1, v2, v3, v4}, Llyiahf/vczjk/za7;-><init>(Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;I)V

    sget-object v1, Llyiahf/vczjk/ym7;->OooO00o:Llyiahf/vczjk/zm7;

    invoke-virtual {v1, v0}, Llyiahf/vczjk/zm7;->OooO0oO(Llyiahf/vczjk/za7;)Llyiahf/vczjk/mh4;

    move-result-object v0

    const/4 v1, 0x1

    new-array v1, v1, [Llyiahf/vczjk/th4;

    aput-object v0, v1, v4

    sput-object v1, Llyiahf/vczjk/xh4;->OooOOo0:[Llyiahf/vczjk/th4;

    return-void
.end method

.method public constructor <init>()V
    .locals 3

    invoke-direct {p0}, Llyiahf/vczjk/ff4;-><init>()V

    new-instance v0, Llyiahf/vczjk/wh4;

    const/4 v1, 0x0

    invoke-direct {v0, p0, v1}, Llyiahf/vczjk/wh4;-><init>(Llyiahf/vczjk/xh4;I)V

    const/4 v1, 0x0

    invoke-static {v1, v0}, Llyiahf/vczjk/vo6;->OooOO0o(Llyiahf/vczjk/eo0;Llyiahf/vczjk/le3;)Llyiahf/vczjk/wm7;

    move-result-object v0

    iput-object v0, p0, Llyiahf/vczjk/xh4;->OooOOOO:Llyiahf/vczjk/wm7;

    sget-object v0, Llyiahf/vczjk/ww4;->OooOOO0:Llyiahf/vczjk/ww4;

    new-instance v1, Llyiahf/vczjk/wh4;

    const/4 v2, 0x1

    invoke-direct {v1, p0, v2}, Llyiahf/vczjk/wh4;-><init>(Llyiahf/vczjk/xh4;I)V

    invoke-static {v0, v1}, Llyiahf/vczjk/jp8;->Oooo00o(Llyiahf/vczjk/ww4;Llyiahf/vczjk/le3;)Llyiahf/vczjk/kp4;

    move-result-object v0

    iput-object v0, p0, Llyiahf/vczjk/xh4;->OooOOOo:Ljava/lang/Object;

    return-void
.end method


# virtual methods
.method public final OooOO0O()Llyiahf/vczjk/so0;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/xh4;->OooOOOo:Ljava/lang/Object;

    invoke-interface {v0}, Llyiahf/vczjk/kp4;->getValue()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/so0;

    return-object v0
.end method

.method public final OooOOO()Llyiahf/vczjk/eo0;
    .locals 2

    sget-object v0, Llyiahf/vczjk/xh4;->OooOOo0:[Llyiahf/vczjk/th4;

    const/4 v1, 0x0

    aget-object v0, v0, v1

    iget-object v0, p0, Llyiahf/vczjk/xh4;->OooOOOO:Llyiahf/vczjk/wm7;

    invoke-virtual {v0}, Llyiahf/vczjk/wm7;->OooO00o()Ljava/lang/Object;

    move-result-object v0

    const-string v1, "getValue(...)"

    invoke-static {v0, v1}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    check-cast v0, Llyiahf/vczjk/va7;

    return-object v0
.end method

.method public final OooOOoo()Llyiahf/vczjk/ka7;
    .locals 2

    sget-object v0, Llyiahf/vczjk/xh4;->OooOOo0:[Llyiahf/vczjk/th4;

    const/4 v1, 0x0

    aget-object v0, v0, v1

    iget-object v0, p0, Llyiahf/vczjk/xh4;->OooOOOO:Llyiahf/vczjk/wm7;

    invoke-virtual {v0}, Llyiahf/vczjk/wm7;->OooO00o()Ljava/lang/Object;

    move-result-object v0

    const-string v1, "getValue(...)"

    invoke-static {v0, v1}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    check-cast v0, Llyiahf/vczjk/va7;

    return-object v0
.end method

.method public final equals(Ljava/lang/Object;)Z
    .locals 1

    instance-of v0, p1, Llyiahf/vczjk/xh4;

    if-eqz v0, :cond_0

    invoke-virtual {p0}, Llyiahf/vczjk/vh4;->OooOo00()Llyiahf/vczjk/ai4;

    move-result-object v0

    check-cast p1, Llyiahf/vczjk/xh4;

    invoke-virtual {p1}, Llyiahf/vczjk/vh4;->OooOo00()Llyiahf/vczjk/ai4;

    move-result-object p1

    invoke-static {v0, p1}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result p1

    if-eqz p1, :cond_0

    const/4 p1, 0x1

    return p1

    :cond_0
    const/4 p1, 0x0

    return p1
.end method

.method public final getName()Ljava/lang/String;
    .locals 3

    new-instance v0, Ljava/lang/StringBuilder;

    const-string v1, "<get-"

    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {p0}, Llyiahf/vczjk/vh4;->OooOo00()Llyiahf/vczjk/ai4;

    move-result-object v1

    iget-object v1, v1, Llyiahf/vczjk/ai4;->OooOOOo:Ljava/lang/String;

    const/16 v2, 0x3e

    invoke-static {v0, v1, v2}, Llyiahf/vczjk/ii5;->OooOO0O(Ljava/lang/StringBuilder;Ljava/lang/String;C)Ljava/lang/String;

    move-result-object v0

    return-object v0
.end method

.method public final hashCode()I
    .locals 1

    invoke-virtual {p0}, Llyiahf/vczjk/vh4;->OooOo00()Llyiahf/vczjk/ai4;

    move-result-object v0

    invoke-virtual {v0}, Llyiahf/vczjk/ai4;->hashCode()I

    move-result v0

    return v0
.end method

.method public final toString()Ljava/lang/String;
    .locals 2

    new-instance v0, Ljava/lang/StringBuilder;

    const-string v1, "getter of "

    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {p0}, Llyiahf/vczjk/vh4;->OooOo00()Llyiahf/vczjk/ai4;

    move-result-object v1

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v0

    return-object v0
.end method
