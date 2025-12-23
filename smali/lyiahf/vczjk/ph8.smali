.class public abstract Llyiahf/vczjk/ph8;
.super Llyiahf/vczjk/lh1;
.source "SourceFile"


# static fields
.field public static final OooOOO:Llyiahf/vczjk/rv2;


# instance fields
.field protected _managedReferenceName:Ljava/lang/String;

.field protected final _nullProvider:Llyiahf/vczjk/u46;

.field protected _objectIdInfo:Llyiahf/vczjk/t66;

.field protected final _propName:Llyiahf/vczjk/xa7;

.field protected _propertyIndex:I

.field protected final _type:Llyiahf/vczjk/x64;

.field protected final _valueDeserializer:Llyiahf/vczjk/e94;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/e94;"
        }
    .end annotation
.end field

.field protected final _valueTypeDeserializer:Llyiahf/vczjk/u3a;

.field protected _viewMatcher:Llyiahf/vczjk/cha;

.field protected final _wrapperName:Llyiahf/vczjk/xa7;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    new-instance v0, Llyiahf/vczjk/rv2;

    invoke-direct {v0}, Llyiahf/vczjk/rv2;-><init>()V

    sput-object v0, Llyiahf/vczjk/ph8;->OooOOO:Llyiahf/vczjk/rv2;

    return-void
.end method

.method public constructor <init>(Llyiahf/vczjk/eb0;Llyiahf/vczjk/x64;Llyiahf/vczjk/u3a;Llyiahf/vczjk/lo;)V
    .locals 7

    invoke-virtual {p1}, Llyiahf/vczjk/eb0;->getFullName()Llyiahf/vczjk/xa7;

    move-result-object v1

    invoke-virtual {p1}, Llyiahf/vczjk/eb0;->OooOOoo()Llyiahf/vczjk/xa7;

    const/4 v3, 0x0

    invoke-virtual {p1}, Llyiahf/vczjk/eb0;->OooO0O0()Llyiahf/vczjk/wa7;

    move-result-object v6

    move-object v0, p0

    move-object v2, p2

    move-object v4, p3

    move-object v5, p4

    invoke-direct/range {v0 .. v6}, Llyiahf/vczjk/ph8;-><init>(Llyiahf/vczjk/xa7;Llyiahf/vczjk/x64;Llyiahf/vczjk/xa7;Llyiahf/vczjk/u3a;Llyiahf/vczjk/lo;Llyiahf/vczjk/wa7;)V

    return-void
.end method

.method public constructor <init>(Llyiahf/vczjk/ph8;)V
    .locals 1

    invoke-direct {p0, p1}, Llyiahf/vczjk/lh1;-><init>(Llyiahf/vczjk/lh1;)V

    const/4 v0, -0x1

    iput v0, p0, Llyiahf/vczjk/ph8;->_propertyIndex:I

    iget-object v0, p1, Llyiahf/vczjk/ph8;->_propName:Llyiahf/vczjk/xa7;

    iput-object v0, p0, Llyiahf/vczjk/ph8;->_propName:Llyiahf/vczjk/xa7;

    iget-object v0, p1, Llyiahf/vczjk/ph8;->_type:Llyiahf/vczjk/x64;

    iput-object v0, p0, Llyiahf/vczjk/ph8;->_type:Llyiahf/vczjk/x64;

    iget-object v0, p1, Llyiahf/vczjk/ph8;->_wrapperName:Llyiahf/vczjk/xa7;

    iput-object v0, p0, Llyiahf/vczjk/ph8;->_wrapperName:Llyiahf/vczjk/xa7;

    iget-object v0, p1, Llyiahf/vczjk/ph8;->_valueDeserializer:Llyiahf/vczjk/e94;

    iput-object v0, p0, Llyiahf/vczjk/ph8;->_valueDeserializer:Llyiahf/vczjk/e94;

    iget-object v0, p1, Llyiahf/vczjk/ph8;->_valueTypeDeserializer:Llyiahf/vczjk/u3a;

    iput-object v0, p0, Llyiahf/vczjk/ph8;->_valueTypeDeserializer:Llyiahf/vczjk/u3a;

    iget-object v0, p1, Llyiahf/vczjk/ph8;->_managedReferenceName:Ljava/lang/String;

    iput-object v0, p0, Llyiahf/vczjk/ph8;->_managedReferenceName:Ljava/lang/String;

    iget v0, p1, Llyiahf/vczjk/ph8;->_propertyIndex:I

    iput v0, p0, Llyiahf/vczjk/ph8;->_propertyIndex:I

    iget-object v0, p1, Llyiahf/vczjk/ph8;->_viewMatcher:Llyiahf/vczjk/cha;

    iput-object v0, p0, Llyiahf/vczjk/ph8;->_viewMatcher:Llyiahf/vczjk/cha;

    iget-object p1, p1, Llyiahf/vczjk/ph8;->_nullProvider:Llyiahf/vczjk/u46;

    iput-object p1, p0, Llyiahf/vczjk/ph8;->_nullProvider:Llyiahf/vczjk/u46;

    return-void
.end method

.method public constructor <init>(Llyiahf/vczjk/ph8;Llyiahf/vczjk/e94;Llyiahf/vczjk/u46;)V
    .locals 1

    invoke-direct {p0, p1}, Llyiahf/vczjk/lh1;-><init>(Llyiahf/vczjk/lh1;)V

    const/4 v0, -0x1

    iput v0, p0, Llyiahf/vczjk/ph8;->_propertyIndex:I

    iget-object v0, p1, Llyiahf/vczjk/ph8;->_propName:Llyiahf/vczjk/xa7;

    iput-object v0, p0, Llyiahf/vczjk/ph8;->_propName:Llyiahf/vczjk/xa7;

    iget-object v0, p1, Llyiahf/vczjk/ph8;->_type:Llyiahf/vczjk/x64;

    iput-object v0, p0, Llyiahf/vczjk/ph8;->_type:Llyiahf/vczjk/x64;

    iget-object v0, p1, Llyiahf/vczjk/ph8;->_wrapperName:Llyiahf/vczjk/xa7;

    iput-object v0, p0, Llyiahf/vczjk/ph8;->_wrapperName:Llyiahf/vczjk/xa7;

    iget-object v0, p1, Llyiahf/vczjk/ph8;->_valueTypeDeserializer:Llyiahf/vczjk/u3a;

    iput-object v0, p0, Llyiahf/vczjk/ph8;->_valueTypeDeserializer:Llyiahf/vczjk/u3a;

    iget-object v0, p1, Llyiahf/vczjk/ph8;->_managedReferenceName:Ljava/lang/String;

    iput-object v0, p0, Llyiahf/vczjk/ph8;->_managedReferenceName:Ljava/lang/String;

    iget v0, p1, Llyiahf/vczjk/ph8;->_propertyIndex:I

    iput v0, p0, Llyiahf/vczjk/ph8;->_propertyIndex:I

    sget-object v0, Llyiahf/vczjk/ph8;->OooOOO:Llyiahf/vczjk/rv2;

    if-nez p2, :cond_0

    iput-object v0, p0, Llyiahf/vczjk/ph8;->_valueDeserializer:Llyiahf/vczjk/e94;

    goto :goto_0

    :cond_0
    iput-object p2, p0, Llyiahf/vczjk/ph8;->_valueDeserializer:Llyiahf/vczjk/e94;

    :goto_0
    iget-object p1, p1, Llyiahf/vczjk/ph8;->_viewMatcher:Llyiahf/vczjk/cha;

    iput-object p1, p0, Llyiahf/vczjk/ph8;->_viewMatcher:Llyiahf/vczjk/cha;

    if-ne p3, v0, :cond_1

    iget-object p3, p0, Llyiahf/vczjk/ph8;->_valueDeserializer:Llyiahf/vczjk/e94;

    :cond_1
    iput-object p3, p0, Llyiahf/vczjk/ph8;->_nullProvider:Llyiahf/vczjk/u46;

    return-void
.end method

.method public constructor <init>(Llyiahf/vczjk/ph8;Llyiahf/vczjk/xa7;)V
    .locals 1

    invoke-direct {p0, p1}, Llyiahf/vczjk/lh1;-><init>(Llyiahf/vczjk/lh1;)V

    const/4 v0, -0x1

    iput v0, p0, Llyiahf/vczjk/ph8;->_propertyIndex:I

    iput-object p2, p0, Llyiahf/vczjk/ph8;->_propName:Llyiahf/vczjk/xa7;

    iget-object p2, p1, Llyiahf/vczjk/ph8;->_type:Llyiahf/vczjk/x64;

    iput-object p2, p0, Llyiahf/vczjk/ph8;->_type:Llyiahf/vczjk/x64;

    iget-object p2, p1, Llyiahf/vczjk/ph8;->_wrapperName:Llyiahf/vczjk/xa7;

    iput-object p2, p0, Llyiahf/vczjk/ph8;->_wrapperName:Llyiahf/vczjk/xa7;

    iget-object p2, p1, Llyiahf/vczjk/ph8;->_valueDeserializer:Llyiahf/vczjk/e94;

    iput-object p2, p0, Llyiahf/vczjk/ph8;->_valueDeserializer:Llyiahf/vczjk/e94;

    iget-object p2, p1, Llyiahf/vczjk/ph8;->_valueTypeDeserializer:Llyiahf/vczjk/u3a;

    iput-object p2, p0, Llyiahf/vczjk/ph8;->_valueTypeDeserializer:Llyiahf/vczjk/u3a;

    iget-object p2, p1, Llyiahf/vczjk/ph8;->_managedReferenceName:Ljava/lang/String;

    iput-object p2, p0, Llyiahf/vczjk/ph8;->_managedReferenceName:Ljava/lang/String;

    iget p2, p1, Llyiahf/vczjk/ph8;->_propertyIndex:I

    iput p2, p0, Llyiahf/vczjk/ph8;->_propertyIndex:I

    iget-object p2, p1, Llyiahf/vczjk/ph8;->_viewMatcher:Llyiahf/vczjk/cha;

    iput-object p2, p0, Llyiahf/vczjk/ph8;->_viewMatcher:Llyiahf/vczjk/cha;

    iget-object p1, p1, Llyiahf/vczjk/ph8;->_nullProvider:Llyiahf/vczjk/u46;

    iput-object p1, p0, Llyiahf/vczjk/ph8;->_nullProvider:Llyiahf/vczjk/u46;

    return-void
.end method

.method public constructor <init>(Llyiahf/vczjk/xa7;Llyiahf/vczjk/x64;Llyiahf/vczjk/wa7;Llyiahf/vczjk/e94;)V
    .locals 0

    invoke-direct {p0, p3}, Llyiahf/vczjk/lh1;-><init>(Llyiahf/vczjk/wa7;)V

    const/4 p3, -0x1

    iput p3, p0, Llyiahf/vczjk/ph8;->_propertyIndex:I

    if-nez p1, :cond_0

    sget-object p1, Llyiahf/vczjk/xa7;->OooOOO:Llyiahf/vczjk/xa7;

    iput-object p1, p0, Llyiahf/vczjk/ph8;->_propName:Llyiahf/vczjk/xa7;

    goto :goto_0

    :cond_0
    invoke-virtual {p1}, Llyiahf/vczjk/xa7;->OooO0o0()Llyiahf/vczjk/xa7;

    move-result-object p1

    iput-object p1, p0, Llyiahf/vczjk/ph8;->_propName:Llyiahf/vczjk/xa7;

    :goto_0
    iput-object p2, p0, Llyiahf/vczjk/ph8;->_type:Llyiahf/vczjk/x64;

    const/4 p1, 0x0

    iput-object p1, p0, Llyiahf/vczjk/ph8;->_wrapperName:Llyiahf/vczjk/xa7;

    iput-object p1, p0, Llyiahf/vczjk/ph8;->_viewMatcher:Llyiahf/vczjk/cha;

    iput-object p1, p0, Llyiahf/vczjk/ph8;->_valueTypeDeserializer:Llyiahf/vczjk/u3a;

    iput-object p4, p0, Llyiahf/vczjk/ph8;->_valueDeserializer:Llyiahf/vczjk/e94;

    iput-object p4, p0, Llyiahf/vczjk/ph8;->_nullProvider:Llyiahf/vczjk/u46;

    return-void
.end method

.method public constructor <init>(Llyiahf/vczjk/xa7;Llyiahf/vczjk/x64;Llyiahf/vczjk/xa7;Llyiahf/vczjk/u3a;Llyiahf/vczjk/lo;Llyiahf/vczjk/wa7;)V
    .locals 0

    invoke-direct {p0, p6}, Llyiahf/vczjk/lh1;-><init>(Llyiahf/vczjk/wa7;)V

    const/4 p5, -0x1

    iput p5, p0, Llyiahf/vczjk/ph8;->_propertyIndex:I

    if-nez p1, :cond_0

    sget-object p1, Llyiahf/vczjk/xa7;->OooOOO:Llyiahf/vczjk/xa7;

    iput-object p1, p0, Llyiahf/vczjk/ph8;->_propName:Llyiahf/vczjk/xa7;

    goto :goto_0

    :cond_0
    invoke-virtual {p1}, Llyiahf/vczjk/xa7;->OooO0o0()Llyiahf/vczjk/xa7;

    move-result-object p1

    iput-object p1, p0, Llyiahf/vczjk/ph8;->_propName:Llyiahf/vczjk/xa7;

    :goto_0
    iput-object p2, p0, Llyiahf/vczjk/ph8;->_type:Llyiahf/vczjk/x64;

    iput-object p3, p0, Llyiahf/vczjk/ph8;->_wrapperName:Llyiahf/vczjk/xa7;

    const/4 p1, 0x0

    iput-object p1, p0, Llyiahf/vczjk/ph8;->_viewMatcher:Llyiahf/vczjk/cha;

    if-eqz p4, :cond_1

    invoke-virtual {p4, p0}, Llyiahf/vczjk/u3a;->OooO0o(Llyiahf/vczjk/db0;)Llyiahf/vczjk/u3a;

    move-result-object p4

    :cond_1
    iput-object p4, p0, Llyiahf/vczjk/ph8;->_valueTypeDeserializer:Llyiahf/vczjk/u3a;

    sget-object p1, Llyiahf/vczjk/ph8;->OooOOO:Llyiahf/vczjk/rv2;

    iput-object p1, p0, Llyiahf/vczjk/ph8;->_valueDeserializer:Llyiahf/vczjk/e94;

    iput-object p1, p0, Llyiahf/vczjk/ph8;->_nullProvider:Llyiahf/vczjk/u46;

    return-void
.end method


# virtual methods
.method public abstract OooO(Llyiahf/vczjk/eb4;Llyiahf/vczjk/v72;Ljava/lang/Object;)V
.end method

.method public final OooO0o(Llyiahf/vczjk/eb4;Ljava/lang/Exception;Ljava/lang/Object;)V
    .locals 2

    instance-of v0, p2, Ljava/lang/IllegalArgumentException;

    if-eqz v0, :cond_1

    invoke-static {p3}, Llyiahf/vczjk/vy0;->OooO0o0(Ljava/lang/Object;)Ljava/lang/String;

    move-result-object p3

    new-instance v0, Ljava/lang/StringBuilder;

    const-string v1, "Problem deserializing property \'"

    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    iget-object v1, p0, Llyiahf/vczjk/ph8;->_propName:Llyiahf/vczjk/xa7;

    invoke-virtual {v1}, Llyiahf/vczjk/xa7;->OooO0OO()Ljava/lang/String;

    move-result-object v1

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    const-string v1, "\' (expected type: "

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    iget-object v1, p0, Llyiahf/vczjk/ph8;->_type:Llyiahf/vczjk/x64;

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    const-string v1, "; actual type: "

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v0, p3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    const-string p3, ")"

    invoke-virtual {v0, p3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-static {p2}, Llyiahf/vczjk/vy0;->OooO0oo(Ljava/lang/Throwable;)Ljava/lang/String;

    move-result-object p3

    if-eqz p3, :cond_0

    const-string v1, ", problem: "

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v0, p3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    goto :goto_0

    :cond_0
    const-string p3, " (no error message provided)"

    invoke-virtual {v0, p3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    :goto_0
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object p3

    new-instance v0, Llyiahf/vczjk/na4;

    invoke-direct {v0, p1, p3, p2}, Llyiahf/vczjk/na4;-><init>(Ljava/io/Closeable;Ljava/lang/String;Ljava/lang/Throwable;)V

    throw v0

    :cond_1
    invoke-static {p2}, Llyiahf/vczjk/vy0;->OooOoO0(Ljava/lang/Throwable;)V

    invoke-static {p2}, Llyiahf/vczjk/vy0;->OooOoO(Ljava/lang/Throwable;)V

    invoke-static {p2}, Llyiahf/vczjk/vy0;->OooOOOO(Ljava/lang/Exception;)Ljava/lang/Throwable;

    move-result-object p2

    invoke-static {p2}, Llyiahf/vczjk/vy0;->OooO0oo(Ljava/lang/Throwable;)Ljava/lang/String;

    move-result-object p3

    new-instance v0, Llyiahf/vczjk/na4;

    invoke-direct {v0, p1, p3, p2}, Llyiahf/vczjk/na4;-><init>(Ljava/io/Closeable;Ljava/lang/String;Ljava/lang/Throwable;)V

    throw v0
.end method

.method public OooO0oO(I)V
    .locals 3

    iget v0, p0, Llyiahf/vczjk/ph8;->_propertyIndex:I

    const/4 v1, -0x1

    if-ne v0, v1, :cond_0

    iput p1, p0, Llyiahf/vczjk/ph8;->_propertyIndex:I

    return-void

    :cond_0
    new-instance v0, Ljava/lang/IllegalStateException;

    new-instance v1, Ljava/lang/StringBuilder;

    const-string v2, "Property \'"

    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    iget-object v2, p0, Llyiahf/vczjk/ph8;->_propName:Llyiahf/vczjk/xa7;

    invoke-virtual {v2}, Llyiahf/vczjk/xa7;->OooO0OO()Ljava/lang/String;

    move-result-object v2

    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    const-string v2, "\' already had index ("

    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    iget v2, p0, Llyiahf/vczjk/ph8;->_propertyIndex:I

    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    const-string v2, "), trying to assign "

    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v1, p1}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object p1

    invoke-direct {v0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw v0
.end method

.method public final OooO0oo(Llyiahf/vczjk/v72;Llyiahf/vczjk/eb4;)Ljava/lang/Object;
    .locals 2

    sget-object v0, Llyiahf/vczjk/gc4;->OooOoO0:Llyiahf/vczjk/gc4;

    invoke-virtual {p2, v0}, Llyiahf/vczjk/eb4;->o0000Oo(Llyiahf/vczjk/gc4;)Z

    move-result v0

    if-eqz v0, :cond_0

    iget-object p2, p0, Llyiahf/vczjk/ph8;->_nullProvider:Llyiahf/vczjk/u46;

    invoke-interface {p2, p1}, Llyiahf/vczjk/u46;->OooO0O0(Llyiahf/vczjk/v72;)Ljava/lang/Object;

    move-result-object p1

    return-object p1

    :cond_0
    iget-object v0, p0, Llyiahf/vczjk/ph8;->_valueTypeDeserializer:Llyiahf/vczjk/u3a;

    if-eqz v0, :cond_1

    iget-object v1, p0, Llyiahf/vczjk/ph8;->_valueDeserializer:Llyiahf/vczjk/e94;

    invoke-virtual {v1, p2, p1, v0}, Llyiahf/vczjk/e94;->OooO0o(Llyiahf/vczjk/eb4;Llyiahf/vczjk/v72;Llyiahf/vczjk/u3a;)Ljava/lang/Object;

    move-result-object p1

    return-object p1

    :cond_1
    iget-object v0, p0, Llyiahf/vczjk/ph8;->_valueDeserializer:Llyiahf/vczjk/e94;

    invoke-virtual {v0, p1, p2}, Llyiahf/vczjk/e94;->OooO0Oo(Llyiahf/vczjk/v72;Llyiahf/vczjk/eb4;)Ljava/lang/Object;

    move-result-object p2

    if-nez p2, :cond_2

    iget-object p2, p0, Llyiahf/vczjk/ph8;->_nullProvider:Llyiahf/vczjk/u46;

    invoke-interface {p2, p1}, Llyiahf/vczjk/u46;->OooO0O0(Llyiahf/vczjk/v72;)Ljava/lang/Object;

    move-result-object p1

    return-object p1

    :cond_2
    return-object p2
.end method

.method public abstract OooOO0(Llyiahf/vczjk/eb4;Llyiahf/vczjk/v72;Ljava/lang/Object;)Ljava/lang/Object;
.end method

.method public final OooOO0O(Llyiahf/vczjk/eb4;Llyiahf/vczjk/v72;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 2

    sget-object v0, Llyiahf/vczjk/gc4;->OooOoO0:Llyiahf/vczjk/gc4;

    invoke-virtual {p1, v0}, Llyiahf/vczjk/eb4;->o0000Oo(Llyiahf/vczjk/gc4;)Z

    move-result v0

    if-eqz v0, :cond_1

    iget-object p1, p0, Llyiahf/vczjk/ph8;->_nullProvider:Llyiahf/vczjk/u46;

    invoke-static {p1}, Llyiahf/vczjk/f56;->OooO00o(Llyiahf/vczjk/u46;)Z

    move-result p1

    if-eqz p1, :cond_0

    goto :goto_0

    :cond_0
    iget-object p1, p0, Llyiahf/vczjk/ph8;->_nullProvider:Llyiahf/vczjk/u46;

    invoke-interface {p1, p2}, Llyiahf/vczjk/u46;->OooO0O0(Llyiahf/vczjk/v72;)Ljava/lang/Object;

    move-result-object p1

    return-object p1

    :cond_1
    iget-object v0, p0, Llyiahf/vczjk/ph8;->_valueTypeDeserializer:Llyiahf/vczjk/u3a;

    if-nez v0, :cond_4

    iget-object v0, p0, Llyiahf/vczjk/ph8;->_valueDeserializer:Llyiahf/vczjk/e94;

    invoke-virtual {v0, p1, p2, p3}, Llyiahf/vczjk/e94;->OooO0o0(Llyiahf/vczjk/eb4;Llyiahf/vczjk/v72;Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    if-nez p1, :cond_3

    iget-object p1, p0, Llyiahf/vczjk/ph8;->_nullProvider:Llyiahf/vczjk/u46;

    invoke-static {p1}, Llyiahf/vczjk/f56;->OooO00o(Llyiahf/vczjk/u46;)Z

    move-result p1

    if-eqz p1, :cond_2

    :goto_0
    return-object p3

    :cond_2
    iget-object p1, p0, Llyiahf/vczjk/ph8;->_nullProvider:Llyiahf/vczjk/u46;

    invoke-interface {p1, p2}, Llyiahf/vczjk/u46;->OooO0O0(Llyiahf/vczjk/v72;)Ljava/lang/Object;

    move-result-object p1

    :cond_3
    return-object p1

    :cond_4
    iget-object p1, p0, Llyiahf/vczjk/ph8;->_type:Llyiahf/vczjk/x64;

    iget-object p3, p0, Llyiahf/vczjk/ph8;->_propName:Llyiahf/vczjk/xa7;

    invoke-virtual {p3}, Llyiahf/vczjk/xa7;->OooO0OO()Ljava/lang/String;

    move-result-object p3

    new-instance v0, Ljava/lang/StringBuilder;

    const-string v1, "Cannot merge polymorphic property \'"

    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {v0, p3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    const-string p3, "\'"

    invoke-virtual {v0, p3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object p3

    invoke-virtual {p2, p1, p3}, Llyiahf/vczjk/v72;->OoooOOO(Llyiahf/vczjk/x64;Ljava/lang/String;)Ljava/lang/Object;

    const/4 p1, 0x0

    throw p1
.end method

.method public OooOO0o(Llyiahf/vczjk/t72;)V
    .locals 0

    return-void
.end method

.method public OooOOO()Ljava/lang/Object;
    .locals 1

    const/4 v0, 0x0

    return-object v0
.end method

.method public OooOOO0()I
    .locals 6

    new-instance v0, Ljava/lang/IllegalStateException;

    iget-object v1, p0, Llyiahf/vczjk/ph8;->_propName:Llyiahf/vczjk/xa7;

    invoke-virtual {v1}, Llyiahf/vczjk/xa7;->OooO0OO()Ljava/lang/String;

    move-result-object v1

    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    move-result-object v2

    invoke-virtual {v2}, Ljava/lang/Class;->getName()Ljava/lang/String;

    move-result-object v2

    const-string v3, "Internal error: no creator index for property \'"

    const-string v4, "\' (of type "

    const-string v5, ")"

    invoke-static {v3, v1, v4, v2, v5}, Llyiahf/vczjk/ii5;->OooOO0(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    move-result-object v1

    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw v0
.end method

.method public OooOOOO()Ljava/lang/String;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/ph8;->_managedReferenceName:Ljava/lang/String;

    return-object v0
.end method

.method public OooOOOo()Llyiahf/vczjk/t66;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/ph8;->_objectIdInfo:Llyiahf/vczjk/t66;

    return-object v0
.end method

.method public OooOOo()Llyiahf/vczjk/u3a;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/ph8;->_valueTypeDeserializer:Llyiahf/vczjk/u3a;

    return-object v0
.end method

.method public OooOOo0()Llyiahf/vczjk/e94;
    .locals 2

    iget-object v0, p0, Llyiahf/vczjk/ph8;->_valueDeserializer:Llyiahf/vczjk/e94;

    sget-object v1, Llyiahf/vczjk/ph8;->OooOOO:Llyiahf/vczjk/rv2;

    if-ne v0, v1, :cond_0

    const/4 v0, 0x0

    :cond_0
    return-object v0
.end method

.method public OooOOoo()Z
    .locals 2

    iget-object v0, p0, Llyiahf/vczjk/ph8;->_valueDeserializer:Llyiahf/vczjk/e94;

    if-eqz v0, :cond_0

    sget-object v1, Llyiahf/vczjk/ph8;->OooOOO:Llyiahf/vczjk/rv2;

    if-eq v0, v1, :cond_0

    const/4 v0, 0x1

    return v0

    :cond_0
    const/4 v0, 0x0

    return v0
.end method

.method public OooOo()V
    .locals 0

    return-void
.end method

.method public OooOo0()Z
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/ph8;->_viewMatcher:Llyiahf/vczjk/cha;

    if-eqz v0, :cond_0

    const/4 v0, 0x1

    return v0

    :cond_0
    const/4 v0, 0x0

    return v0
.end method

.method public OooOo00()Z
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/ph8;->_valueTypeDeserializer:Llyiahf/vczjk/u3a;

    if-eqz v0, :cond_0

    const/4 v0, 0x1

    return v0

    :cond_0
    const/4 v0, 0x0

    return v0
.end method

.method public OooOo0O()Z
    .locals 1

    const/4 v0, 0x0

    return v0
.end method

.method public OooOo0o()Z
    .locals 1

    const/4 v0, 0x0

    return v0
.end method

.method public abstract OooOoO(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
.end method

.method public abstract OooOoO0(Ljava/lang/Object;Ljava/lang/Object;)V
.end method

.method public final OooOoOO([Ljava/lang/Class;)V
    .locals 2

    if-nez p1, :cond_0

    const/4 p1, 0x0

    iput-object p1, p0, Llyiahf/vczjk/ph8;->_viewMatcher:Llyiahf/vczjk/cha;

    return-void

    :cond_0
    sget-object v0, Llyiahf/vczjk/cha;->OooOOO0:Llyiahf/vczjk/cha;

    array-length v1, p1

    if-eqz v1, :cond_2

    const/4 v0, 0x1

    if-eq v1, v0, :cond_1

    new-instance v0, Llyiahf/vczjk/aha;

    invoke-direct {v0, p1}, Llyiahf/vczjk/aha;-><init>([Ljava/lang/Class;)V

    goto :goto_0

    :cond_1
    new-instance v0, Llyiahf/vczjk/bha;

    const/4 v1, 0x0

    aget-object p1, p1, v1

    invoke-direct {v0, p1}, Llyiahf/vczjk/bha;-><init>(Ljava/lang/Class;)V

    :cond_2
    :goto_0
    iput-object v0, p0, Llyiahf/vczjk/ph8;->_viewMatcher:Llyiahf/vczjk/cha;

    return-void
.end method

.method public abstract OooOoo(Llyiahf/vczjk/xa7;)Llyiahf/vczjk/ph8;
.end method

.method public OooOoo0(Ljava/lang/Class;)Z
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/ph8;->_viewMatcher:Llyiahf/vczjk/cha;

    if-eqz v0, :cond_1

    invoke-virtual {v0, p1}, Llyiahf/vczjk/cha;->OooO00o(Ljava/lang/Class;)Z

    move-result p1

    if-eqz p1, :cond_0

    goto :goto_0

    :cond_0
    const/4 p1, 0x0

    return p1

    :cond_1
    :goto_0
    const/4 p1, 0x1

    return p1
.end method

.method public abstract OooOooO(Llyiahf/vczjk/u46;)Llyiahf/vczjk/ph8;
.end method

.method public final OooOooo(Ljava/lang/String;)Llyiahf/vczjk/ph8;
    .locals 2

    iget-object v0, p0, Llyiahf/vczjk/ph8;->_propName:Llyiahf/vczjk/xa7;

    if-nez v0, :cond_0

    new-instance v0, Llyiahf/vczjk/xa7;

    const/4 v1, 0x0

    invoke-direct {v0, p1, v1}, Llyiahf/vczjk/xa7;-><init>(Ljava/lang/String;Ljava/lang/String;)V

    goto :goto_0

    :cond_0
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    if-nez p1, :cond_1

    const-string p1, ""

    :cond_1
    iget-object v1, v0, Llyiahf/vczjk/xa7;->_simpleName:Ljava/lang/String;

    invoke-virtual {p1, v1}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v1

    if-eqz v1, :cond_2

    goto :goto_0

    :cond_2
    new-instance v1, Llyiahf/vczjk/xa7;

    iget-object v0, v0, Llyiahf/vczjk/xa7;->_namespace:Ljava/lang/String;

    invoke-direct {v1, p1, v0}, Llyiahf/vczjk/xa7;-><init>(Ljava/lang/String;Ljava/lang/String;)V

    move-object v0, v1

    :goto_0
    iget-object p1, p0, Llyiahf/vczjk/ph8;->_propName:Llyiahf/vczjk/xa7;

    if-ne v0, p1, :cond_3

    return-object p0

    :cond_3
    invoke-virtual {p0, v0}, Llyiahf/vczjk/ph8;->OooOoo(Llyiahf/vczjk/xa7;)Llyiahf/vczjk/ph8;

    move-result-object p1

    return-object p1
.end method

.method public abstract Oooo000(Llyiahf/vczjk/e94;)Llyiahf/vczjk/ph8;
.end method

.method public final getFullName()Llyiahf/vczjk/xa7;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/ph8;->_propName:Llyiahf/vczjk/xa7;

    return-object v0
.end method

.method public final getName()Ljava/lang/String;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/ph8;->_propName:Llyiahf/vczjk/xa7;

    invoke-virtual {v0}, Llyiahf/vczjk/xa7;->OooO0OO()Ljava/lang/String;

    move-result-object v0

    return-object v0
.end method

.method public final getType()Llyiahf/vczjk/x64;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/ph8;->_type:Llyiahf/vczjk/x64;

    return-object v0
.end method

.method public toString()Ljava/lang/String;
    .locals 2

    new-instance v0, Ljava/lang/StringBuilder;

    const-string v1, "[property \'"

    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    iget-object v1, p0, Llyiahf/vczjk/ph8;->_propName:Llyiahf/vczjk/xa7;

    invoke-virtual {v1}, Llyiahf/vczjk/xa7;->OooO0OO()Ljava/lang/String;

    move-result-object v1

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    const-string v1, "\']"

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v0

    return-object v0
.end method
